from __future__ import annotations

import shlex
from typing import Iterable

from contrace.runtime import RuntimeSpec


def _shell_quote(value: str) -> str:
    return shlex.quote(value)


def _render_env_exports(env: dict[str, str]) -> str:
    return "\n".join(f"export {key}={_shell_quote(value)}" for key, value in sorted(env.items()))


def _render_command_argv(spec: RuntimeSpec) -> list[str]:
    if not spec.shell_mode:
        return spec.argv
    shell_argv = list(spec.shell_argv or ["/bin/sh", "-c"])
    command_text = " ".join(_shell_quote(item) for item in spec.argv)
    return [*shell_argv, command_text]


def render_watchdog_script() -> str:
    return """#!/bin/sh
set -eu

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

MODE="$1"
PORT="$2"
STATE_FILE="$3"
PID_FILE="${4:-}"
FALLBACK_PID_FILE="${5:-}"

mkdir -p /run/contrace

case "$MODE" in
  multi)
    while :; do
      /usr/bin/gdbserver --multi "0.0.0.0:${PORT}" >>"$STATE_FILE" 2>&1 || true
      echo "[contrace] gdbserver multi exited, restarting" >>"$STATE_FILE"
      sleep 1
    done
    ;;
  attach)
    ATTACH_DELAY="${CONTRACE_ATTACH_DELAY:-2}"
    while :; do
      CANDIDATE_FILE=
      if [ -n "$PID_FILE" ] && [ -r "$PID_FILE" ] && [ -s "$PID_FILE" ]; then
        CANDIDATE_FILE="$PID_FILE"
      elif [ -n "$FALLBACK_PID_FILE" ] && [ -r "$FALLBACK_PID_FILE" ] && [ -s "$FALLBACK_PID_FILE" ]; then
        CANDIDATE_FILE="$FALLBACK_PID_FILE"
      fi
      if [ -n "$CANDIDATE_FILE" ]; then
        PID="$(cat "$CANDIDATE_FILE" 2>/dev/null || true)"
        if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
          sleep "$ATTACH_DELAY"
          if ! kill -0 "$PID" 2>/dev/null; then
            sleep 1
            continue
          fi
          /usr/bin/gdbserver --attach "0.0.0.0:${PORT}" "$PID" >>"$STATE_FILE" 2>&1 || true
          echo "[contrace] gdbserver attach exited, retrying" >>"$STATE_FILE"
        else
          echo "[contrace] waiting for service pid" >>"$STATE_FILE"
        fi
      fi
      sleep 1
    done
    ;;
  *)
    echo "usage: $0 <multi|attach> <port> <state-file> [pid-file]" >&2
    exit 2
    ;;
esac
"""


def render_child_wrap_script() -> str:
    return """#!/bin/sh
set -eu

TARGET="${CONTRACE_EXEC_TARGET:-}"
if [ -z "$TARGET" ]; then
  echo "[contrace] child wrapper missing CONTRACE_EXEC_TARGET" >&2
  exit 111
fi

if [ -w /run/contrace/last-child.pid ]; then
  printf '%s\n' "$$" >/run/contrace/last-child.pid
fi

exec /bin/sh -c "exec $TARGET"
"""


def render_init_script(
    spec: RuntimeSpec,
    *,
    busybox_path: str,
    helper_path: str | None,
    direct_exec_ok: bool,
) -> str:
    command_argv = _render_command_argv(spec)
    argv_lines = "\n".join(f'  "{item}" \\' for item in command_argv[:-1])
    argv_tail = f'  "{command_argv[-1]}"'
    command_block = f"{argv_lines}\n{argv_tail}" if argv_lines else argv_tail
    group_csv = ",".join(str(item) for item in spec.supplementary_gids) or "-"

    if helper_path is not None:
        launch_prefix = (
            f'"{helper_path}" "{spec.workdir}" "{spec.uid}" "{spec.gid}" "{group_csv}" --'
        )
        launcher = f"""{launch_prefix} \\
{command_block} &
"""
        launcher = launcher.replace("&\n", ">/run/contrace/service.log 2>&1 &\n")
    elif direct_exec_ok:
        launcher = f"""(
  cd "{spec.workdir}" || exit 111
  exec \\
{command_block}
) >/run/contrace/service.log 2>&1 &
"""
    else:
        raise ValueError("helper_path required for non-root launches")

    attach_block = ""
    if spec.debug_attach_port:
        attach_block = f"""
if [ -x /usr/libexec/contrace-watchdog.sh ]; then
  /usr/libexec/contrace-watchdog.sh attach "{spec.debug_attach_port}" /run/contrace/gdb-attach.state /run/contrace/last-child.pid /run/contrace/service.pid &
fi
"""

    env_exports = _render_env_exports(spec.env)
    if spec.socat_exec_target:
        env_exports = (
            env_exports
            + ("\n" if env_exports else "")
            + f"export CONTRACE_EXEC_TARGET={_shell_quote(spec.socat_exec_target)}"
        )
    service_ports = ",".join(str(port) for port in spec.service_ports) or "(none)"
    keep_shell_block = f"""echo "=== contrace guest ready ==="
echo "service pid:   $SERVICE_PID"
echo "service ports: {service_ports}"
echo "gdb multi:     {spec.debug_multi_port}"
echo "gdb attach:    {spec.debug_attach_port} (best-effort)"
echo "tracefs:       /sys/kernel/tracing"
echo "runtime:       /etc/contrace/runtime.json"
echo "trace pipe:    cat /sys/kernel/tracing/trace_pipe"
echo "enable event:  echo 1 > /sys/kernel/tracing/events/syscalls/enable"
echo "record:        trace-cmd record -e syscalls"
export PS1='(contrace) # '
if [ -c /dev/ttyS0 ]; then
  SHELL_TTY=/dev/ttyS0
elif [ -c /dev/console ]; then
  SHELL_TTY=/dev/console
else
  SHELL_TTY=
fi
if [ -n "$SHELL_TTY" ]; then
  "{busybox_path}" sh <"$SHELL_TTY" >"$SHELL_TTY" 2>&1 &
  echo $! >/run/contrace/shell.pid
fi
set +e
wait "$SERVICE_PID"
STATUS="$?"
set -e
if [ "$STATUS" -ne 0 ] && [ -f /run/contrace/service.log ]; then
  cat /run/contrace/service.log
fi
echo "exited:${{STATUS}}" >/run/contrace/service.state
exit "$STATUS"
"""
    no_shell_block = """set +e
wait "$SERVICE_PID"
STATUS="$?"
set -e
if [ "$STATUS" -ne 0 ] && [ -f /run/contrace/service.log ]; then
  cat /run/contrace/service.log
fi
echo "exited:${STATUS}" >/run/contrace/service.state
exit "$STATUS"
"""
    return f"""#!{busybox_path} sh
set -eu

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

BUSYBOX="{busybox_path}"

mount_fs() {{
  "$BUSYBOX" mkdir -p /proc /sys /dev /run /tmp /etc/contrace
  "$BUSYBOX" mount -t proc proc /proc
  "$BUSYBOX" mount -t sysfs sysfs /sys
  "$BUSYBOX" mount -t devtmpfs devtmpfs /dev
  "$BUSYBOX" mount -t tmpfs tmpfs /run
  "$BUSYBOX" mount -t tmpfs tmpfs /tmp
  "$BUSYBOX" mkdir -p /dev/pts /sys/kernel/debug /sys/kernel/tracing /run/contrace
  "$BUSYBOX" mount -t devpts devpts /dev/pts
  "$BUSYBOX" mkdir -p /run/contrace
  : >/run/contrace/last-child.pid
  chmod 0666 /run/contrace/last-child.pid
  "$BUSYBOX" mount -t debugfs debugfs /sys/kernel/debug || true
  "$BUSYBOX" mount -t tracefs tracefs /sys/kernel/tracing || true
}}

configure_network() {{
  "$BUSYBOX" hostname "{spec.hostname}" || true
  "$BUSYBOX" ip link set lo up || true
  "$BUSYBOX" ip link set eth0 up || true
  "$BUSYBOX" ip addr add 10.0.2.15/24 dev eth0 || true
  "$BUSYBOX" ip route add default via 10.0.2.2 dev eth0 || true
}}

apply_trace_preset() {{
  TRACE_ROOT=/sys/kernel/tracing
  [ -d "$TRACE_ROOT" ] || return 0
  echo 0 >"$TRACE_ROOT/tracing_on" 2>/dev/null || true
  echo nop >"$TRACE_ROOT/current_tracer" 2>/dev/null || true
  for path in "$TRACE_ROOT"/events/*/enable; do
    [ -e "$path" ] || continue
    echo 0 >"$path" 2>/dev/null || true
  done
  case "{spec.trace_preset}" in
    off) ;;
    syscalls) echo 1 >"$TRACE_ROOT/events/syscalls/enable" 2>/dev/null || true ;;
    sched) echo 1 >"$TRACE_ROOT/events/sched/enable" 2>/dev/null || true ;;
    kmem) echo 1 >"$TRACE_ROOT/events/kmem/enable" 2>/dev/null || true ;;
    net) echo 1 >"$TRACE_ROOT/events/net/enable" 2>/dev/null || true ;;
  esac
  echo 1 >"$TRACE_ROOT/tracing_on" 2>/dev/null || true
}}

start_watchdogs() {{
  if [ -x /usr/libexec/contrace-watchdog.sh ]; then
    /usr/libexec/contrace-watchdog.sh multi "{spec.debug_multi_port}" /run/contrace/gdb-multi.state &
  fi
}}

launch_service() {{
{env_exports}
{launcher}  SERVICE_PID="$!"
  echo "$SERVICE_PID" >/run/contrace/service.pid
  echo "running" >/run/contrace/service.state
}}

main() {{
  echo "[contrace:init] mount_fs"
  mount_fs
  echo "[contrace:init] configure_network"
  configure_network
  echo "[contrace:init] apply_trace_preset"
  apply_trace_preset
  echo "[contrace:init] start_watchdogs"
  start_watchdogs
  echo "[contrace:init] launch_service"
  launch_service
  echo "[contrace:init] service pid $SERVICE_PID"
{attach_block}
{keep_shell_block if spec.keep_shell else no_shell_block}
}}

main "$@"
"""
