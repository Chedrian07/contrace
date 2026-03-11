from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from contrace.errors import ContraceError, ExitCode

TRACE_PRESETS = {"off", "syscalls", "sched", "kmem", "net"}
GUEST_ARCHES = {"x86_64"}


@dataclass(slots=True)
class ForwardMapping:
    host: int
    guest: int


@dataclass(slots=True)
class GuestConfig:
    arch: str | None = None
    memory: str | None = None
    cpus: int | None = None
    hostname: str | None = None


@dataclass(slots=True)
class RuntimeConfig:
    user: str | None = None
    workdir: str | None = None
    argv: list[str] | None = None
    shell_mode: bool | None = None
    shell_argv: list[str] | None = None
    env: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class PortsConfig:
    service: list[int] = field(default_factory=list)
    forwards: list[ForwardMapping] = field(default_factory=list)


@dataclass(slots=True)
class DebugConfig:
    gdb_multi_port: int | None = None
    gdb_attach_port: int | None = None
    enable_attach: bool | None = None
    qemu_gdb_port: int | None = None


@dataclass(slots=True)
class TraceConfig:
    preset: str | None = None


@dataclass(slots=True)
class PolicyConfig:
    allow_root_fallback: bool | None = None
    keep_shell: bool | None = None
    infer_ports: bool | None = None


@dataclass(slots=True)
class FileConfig:
    version: int = 1
    guest: GuestConfig = field(default_factory=GuestConfig)
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)
    ports: PortsConfig = field(default_factory=PortsConfig)
    debug: DebugConfig = field(default_factory=DebugConfig)
    trace: TraceConfig = field(default_factory=TraceConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)


@dataclass(slots=True)
class CliOverrides:
    guest_arch: str | None
    memory: str | None
    cpus: int | None
    host_workdir: Path | None
    keep_workdir: bool
    explicit_config: Path | None
    ports: list[ForwardMapping]
    trace_preset: str | None
    env: dict[str, str]
    runtime_user: str | None
    argv: list[str] | None
    shell_mode: bool | None
    hostname: str | None
    gdb_multi_port: int | None
    gdb_attach_port: int | None
    enable_attach: bool | None
    qemu_gdb_port: int | None
    keep_shell: bool | None
    allow_root_fallback: bool
    verbose: int
    dry_run: bool


@dataclass(slots=True)
class ResolvedConfig:
    guest_arch: str
    memory: str
    cpus: int
    hostname: str
    runtime_user: str | None
    runtime_workdir: str | None
    argv: list[str] | None
    shell_mode: bool
    shell_argv: list[str] | None
    env: dict[str, str]
    service_ports: list[int]
    forwards: list[ForwardMapping]
    trace_preset: str
    gdb_multi_port: int
    gdb_attach_port: int
    enable_attach: bool
    qemu_gdb_port: int | None
    allow_root_fallback: bool
    keep_shell: bool
    infer_ports: bool

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["forwards"] = [asdict(item) for item in self.forwards]
        return payload


def _validate_mapping(name: str, value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ContraceError(f"{name} must be a mapping", ExitCode.INVALID_INPUT)
    return value


def _reject_unknown(name: str, data: dict[str, Any], allowed: set[str]) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ContraceError(
            f"unknown field(s) in {name}: {', '.join(unknown)}",
            ExitCode.INVALID_INPUT,
        )


def _parse_int(name: str, value: Any) -> int:
    if not isinstance(value, int):
        raise ContraceError(f"{name} must be an integer", ExitCode.INVALID_INPUT)
    return value


def _parse_bool(name: str, value: Any) -> bool:
    if not isinstance(value, bool):
        raise ContraceError(f"{name} must be a boolean", ExitCode.INVALID_INPUT)
    return value


def _parse_str(name: str, value: Any) -> str:
    if not isinstance(value, str):
        raise ContraceError(f"{name} must be a string", ExitCode.INVALID_INPUT)
    return value


def _parse_trace_preset(value: Any) -> str:
    if value is False:
        return "off"
    if not isinstance(value, str):
        raise ContraceError("trace.preset must be a string", ExitCode.INVALID_INPUT)
    return value


def _parse_str_list(name: str, value: Any) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ContraceError(f"{name} must be a list of strings", ExitCode.INVALID_INPUT)
    return list(value)


def parse_forward(value: str) -> ForwardMapping:
    parts = value.split(":", 1)
    if len(parts) != 2:
        raise ContraceError(
            f"invalid port mapping '{value}', expected HOST:GUEST",
            ExitCode.INVALID_INPUT,
        )
    try:
        host = int(parts[0])
        guest = int(parts[1])
    except ValueError as exc:
        raise ContraceError(
            f"invalid port mapping '{value}', expected numeric HOST:GUEST",
            ExitCode.INVALID_INPUT,
        ) from exc
    return ForwardMapping(host=host, guest=guest)


def parse_env_assignment(value: str) -> tuple[str, str]:
    key, sep, raw_value = value.partition("=")
    if not sep or not key:
        raise ContraceError(
            f"invalid env override '{value}', expected KEY=VALUE",
            ExitCode.INVALID_INPUT,
        )
    return key, raw_value


def cli_overrides_from_args(args: Any) -> CliOverrides:
    env: dict[str, str] = {}
    for item in args.env or []:
        key, value = parse_env_assignment(item)
        env[key] = value

    argv = json.loads(args.argv) if args.argv else None
    if argv is not None:
        if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
            raise ContraceError("--argv must be a JSON array of strings", ExitCode.INVALID_INPUT)

    return CliOverrides(
        guest_arch=args.guest_arch,
        memory=args.memory,
        cpus=args.cpus,
        host_workdir=Path(args.workdir).expanduser() if args.workdir else None,
        keep_workdir=args.keep_workdir,
        explicit_config=Path(args.config).expanduser() if args.config else None,
        ports=[parse_forward(item) for item in args.port or []],
        trace_preset=args.trace,
        env=env,
        runtime_user=args.user,
        argv=argv,
        shell_mode=args.shell_mode,
        hostname=args.hostname,
        gdb_multi_port=args.gdb_multi_port,
        gdb_attach_port=args.gdb_attach_port,
        enable_attach=True if getattr(args, "enable_gdb_attach", False) else (False if args.disable_gdb_attach else None),
        qemu_gdb_port=args.qemu_gdb_port,
        keep_shell=args.keep_shell,
        allow_root_fallback=args.allow_root_fallback,
        verbose=args.verbose or 0,
        dry_run=getattr(args, "dry_run", False),
    )


def load_file_config(path: Path | None) -> FileConfig:
    if path is None:
        return FileConfig()
    if not path.exists():
        raise ContraceError(f"config file not found: {path}", ExitCode.INVALID_INPUT)

    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        raise ContraceError("config root must be a mapping", ExitCode.INVALID_INPUT)

    _reject_unknown(
        "config",
        payload,
        {"version", "guest", "runtime", "ports", "debug", "trace", "policy"},
    )

    version = payload.get("version", 1)
    if version != 1:
        raise ContraceError("only config version 1 is supported", ExitCode.INVALID_INPUT)

    guest_raw = _validate_mapping("guest", payload.get("guest"))
    runtime_raw = _validate_mapping("runtime", payload.get("runtime"))
    ports_raw = _validate_mapping("ports", payload.get("ports"))
    debug_raw = _validate_mapping("debug", payload.get("debug"))
    trace_raw = _validate_mapping("trace", payload.get("trace"))
    policy_raw = _validate_mapping("policy", payload.get("policy"))

    _reject_unknown("guest", guest_raw, {"arch", "memory", "cpus", "hostname"})
    _reject_unknown("runtime", runtime_raw, {"user", "workdir", "argv", "shell_mode", "shell_argv", "env"})
    _reject_unknown("ports", ports_raw, {"service", "forwards"})
    _reject_unknown("debug", debug_raw, {"gdb_multi_port", "gdb_attach_port", "enable_attach", "qemu_gdb_port"})
    _reject_unknown("trace", trace_raw, {"preset"})
    _reject_unknown("policy", policy_raw, {"allow_root_fallback", "keep_shell", "infer_ports"})

    guest = GuestConfig(
        arch=_parse_str("guest.arch", guest_raw["arch"]) if "arch" in guest_raw else None,
        memory=_parse_str("guest.memory", guest_raw["memory"]) if "memory" in guest_raw else None,
        cpus=_parse_int("guest.cpus", guest_raw["cpus"]) if "cpus" in guest_raw else None,
        hostname=_parse_str("guest.hostname", guest_raw["hostname"]) if "hostname" in guest_raw else None,
    )
    runtime = RuntimeConfig(
        user=_parse_str("runtime.user", runtime_raw["user"]) if "user" in runtime_raw else None,
        workdir=_parse_str("runtime.workdir", runtime_raw["workdir"]) if "workdir" in runtime_raw else None,
        argv=_parse_str_list("runtime.argv", runtime_raw["argv"]) if "argv" in runtime_raw else None,
        shell_mode=_parse_bool("runtime.shell_mode", runtime_raw["shell_mode"])
        if "shell_mode" in runtime_raw
        else None,
        shell_argv=_parse_str_list("runtime.shell_argv", runtime_raw["shell_argv"])
        if "shell_argv" in runtime_raw
        else None,
        env={},
    )
    env_raw = runtime_raw.get("env")
    if env_raw is not None:
        if not isinstance(env_raw, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in env_raw.items()
        ):
            raise ContraceError("runtime.env must be a mapping of strings", ExitCode.INVALID_INPUT)
        runtime.env = dict(env_raw)

    ports = PortsConfig(
        service=[],
        forwards=[],
    )
    if "service" in ports_raw:
        service = ports_raw["service"]
        if not isinstance(service, list) or not all(isinstance(item, int) for item in service):
            raise ContraceError("ports.service must be a list of integers", ExitCode.INVALID_INPUT)
        ports.service = list(service)
    if "forwards" in ports_raw:
        forwards = ports_raw["forwards"]
        if not isinstance(forwards, list) or not all(isinstance(item, str) for item in forwards):
            raise ContraceError("ports.forwards must be a list of HOST:GUEST strings", ExitCode.INVALID_INPUT)
        ports.forwards = [parse_forward(item) for item in forwards]

    debug = DebugConfig(
        gdb_multi_port=_parse_int("debug.gdb_multi_port", debug_raw["gdb_multi_port"])
        if "gdb_multi_port" in debug_raw
        else None,
        gdb_attach_port=_parse_int("debug.gdb_attach_port", debug_raw["gdb_attach_port"])
        if "gdb_attach_port" in debug_raw
        else None,
        enable_attach=_parse_bool("debug.enable_attach", debug_raw["enable_attach"])
        if "enable_attach" in debug_raw
        else None,
        qemu_gdb_port=None,
    )
    if "qemu_gdb_port" in debug_raw:
        if debug_raw["qemu_gdb_port"] is not None and not isinstance(debug_raw["qemu_gdb_port"], int):
            raise ContraceError("debug.qemu_gdb_port must be an integer or null", ExitCode.INVALID_INPUT)
        debug.qemu_gdb_port = debug_raw["qemu_gdb_port"]

    trace = TraceConfig(
        preset=_parse_trace_preset(trace_raw["preset"]) if "preset" in trace_raw else None,
    )
    policy = PolicyConfig(
        allow_root_fallback=_parse_bool("policy.allow_root_fallback", policy_raw["allow_root_fallback"])
        if "allow_root_fallback" in policy_raw
        else None,
        keep_shell=_parse_bool("policy.keep_shell", policy_raw["keep_shell"])
        if "keep_shell" in policy_raw
        else None,
        infer_ports=_parse_bool("policy.infer_ports", policy_raw["infer_ports"])
        if "infer_ports" in policy_raw
        else None,
    )

    return FileConfig(
        version=version,
        guest=guest,
        runtime=runtime,
        ports=ports,
        debug=debug,
        trace=trace,
        policy=policy,
    )


def resolve_config(file_config: FileConfig, overrides: CliOverrides) -> ResolvedConfig:
    guest_arch = overrides.guest_arch or file_config.guest.arch or "x86_64"
    if guest_arch not in GUEST_ARCHES:
        raise ContraceError(f"unsupported guest arch: {guest_arch}", ExitCode.INVALID_INPUT)

    trace_preset = overrides.trace_preset or file_config.trace.preset or "syscalls"
    if trace_preset not in TRACE_PRESETS:
        raise ContraceError(f"invalid trace preset: {trace_preset}", ExitCode.INVALID_INPUT)

    env = dict(file_config.runtime.env)
    env.update(overrides.env)

    forwards_by_guest: dict[int, ForwardMapping] = {
        item.guest: item for item in file_config.ports.forwards
    }
    for item in overrides.ports:
        forwards_by_guest[item.guest] = item

    resolved = ResolvedConfig(
        guest_arch=guest_arch,
        memory=overrides.memory or file_config.guest.memory or "512M",
        cpus=overrides.cpus or file_config.guest.cpus or 1,
        hostname=overrides.hostname or file_config.guest.hostname or "contrace",
        runtime_user=overrides.runtime_user or file_config.runtime.user,
        runtime_workdir=file_config.runtime.workdir,
        argv=overrides.argv or file_config.runtime.argv,
        shell_mode=overrides.shell_mode
        if overrides.shell_mode is not None
        else (file_config.runtime.shell_mode if file_config.runtime.shell_mode is not None else False),
        shell_argv=file_config.runtime.shell_argv,
        env=env,
        service_ports=list(file_config.ports.service),
        forwards=list(forwards_by_guest.values()),
        trace_preset=trace_preset,
        gdb_multi_port=overrides.gdb_multi_port or file_config.debug.gdb_multi_port or 1234,
        gdb_attach_port=overrides.gdb_attach_port or file_config.debug.gdb_attach_port or 1235,
        enable_attach=overrides.enable_attach
        if overrides.enable_attach is not None
        else (file_config.debug.enable_attach if file_config.debug.enable_attach is not None else False),
        qemu_gdb_port=overrides.qemu_gdb_port
        if overrides.qemu_gdb_port is not None
        else file_config.debug.qemu_gdb_port,
        allow_root_fallback=overrides.allow_root_fallback
        or bool(file_config.policy.allow_root_fallback),
        keep_shell=overrides.keep_shell
        if overrides.keep_shell is not None
        else (file_config.policy.keep_shell if file_config.policy.keep_shell is not None else True),
        infer_ports=file_config.policy.infer_ports if file_config.policy.infer_ports is not None else True,
    )
    return resolved
