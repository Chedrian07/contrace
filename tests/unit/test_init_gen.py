from contrace.init_gen import render_init_script, render_watchdog_script
from contrace.runtime import RuntimeSpec


def test_render_init_script_includes_trace_and_watchdogs() -> None:
    spec = RuntimeSpec(
        guest_arch="x86_64",
        env={"TERM": "xterm-256color"},
        workdir="/home/ctf",
        uid=1000,
        gid=1000,
        supplementary_gids=[1001],
        argv=["/home/ctf/chall"],
        shell_mode=False,
        shell_argv=None,
        manager="socat",
        service_ports=[31337],
        debug_multi_port=1234,
        debug_attach_port=1235,
        trace_preset="syscalls",
        hostname="contrace",
        keep_shell=True,
        socat_exec_target="/home/ctf/chall",
        attach_mode="child",
        attach_target_exe="/home/ctf/chall",
    )

    init_script = render_init_script(spec, busybox_path="/bin/busybox", helper_path="/usr/libexec/contrace-exec", direct_exec_ok=False)
    watchdog = render_watchdog_script()
    assert "events/syscalls/enable" in init_script
    assert "/usr/libexec/contrace-watchdog.sh multi" in init_script
    assert "/usr/libexec/contrace-watchdog.sh attach" in init_script
    assert "/run/contrace/last-child.pid" in init_script
    assert "/run/contrace/attach-current.pid" in init_script
    assert "/run/contrace/attach-mode" in init_script
    assert "/run/contrace/attach-target.exe" in init_script
    if spec.socat_exec_target is not None:
        attach_line = '/usr/libexec/contrace-watchdog.sh attach "1235" /run/contrace/gdb-attach.state /run/contrace/last-child.pid'
        assert attach_line in init_script
        assert "export CONTRACE_ATTACH_MODE=socat" not in init_script
        assert "export CONTRACE_ATTACH_MODE=child" in init_script
        assert "waiting for child" in init_script
    assert "gdbserver --multi" in watchdog
    assert "attach target changed" in watchdog
    assert "attach-current.pid" in watchdog
    assert "ATTACH_TARGET_EXE" in watchdog
    assert "poweroff | reboot | halt" in init_script
