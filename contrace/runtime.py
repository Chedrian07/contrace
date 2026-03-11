from __future__ import annotations

import json
import logging
import re
import tarfile
from dataclasses import asdict, dataclass, field
from pathlib import PurePosixPath
from typing import Any

from contrace.config import ResolvedConfig
from contrace.detect import classify_manager, infer_ports_from_argv, parse_inetd_conf, parse_xinetd_configs
from contrace.errors import ContraceError, ExitCode

LOGGER = logging.getLogger(__name__)

DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


@dataclass(slots=True)
class RuntimeDiagnostics:
    source_of_user: str
    source_of_ports: str
    source_of_argv: str
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RuntimeSpec:
    guest_arch: str
    env: dict[str, str]
    workdir: str
    uid: int
    gid: int
    supplementary_gids: list[int]
    argv: list[str]
    shell_mode: bool
    shell_argv: list[str] | None
    manager: str
    service_ports: list[int]
    debug_multi_port: int
    debug_attach_port: int
    trace_preset: str
    hostname: str
    keep_shell: bool
    socat_exec_target: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class RuntimeBundle:
    spec: RuntimeSpec
    diagnostics: RuntimeDiagnostics

    def to_dict(self) -> dict[str, Any]:
        return {
            "runtime": self.spec.to_dict(),
            "diagnostics": self.diagnostics.to_dict(),
        }


@dataclass(slots=True)
class PasswdEntry:
    name: str
    uid: int
    gid: int
    gecos: str
    home: str
    shell: str


@dataclass(slots=True)
class GroupEntry:
    name: str
    gid: int
    members: list[str]


@dataclass(slots=True)
class DockerMetadata:
    user: str
    workdir: str
    env: dict[str, str]
    entrypoint: list[str]
    cmd: list[str]
    exposed_ports: list[int]


class TarFilesystemView:
    def __init__(self, tar_path: str) -> None:
        self.tar_path = tar_path
        self._handle: tarfile.TarFile | None = None
        self._members: dict[str, tarfile.TarInfo] = {}

    def __enter__(self) -> "TarFilesystemView":
        self._handle = tarfile.open(self.tar_path)
        self._members = {self._normalize(member.name): member for member in self._handle.getmembers()}
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        if self._handle is not None:
            self._handle.close()
        self._handle = None
        self._members = {}

    def _normalize(self, path: str) -> str:
        candidate = PurePosixPath(path)
        parts = [part for part in candidate.parts if part not in {"", "."}]
        if parts and parts[0] == "/":
            parts = parts[1:]
        return "/".join(parts).lstrip("/")

    def exists(self, path: str) -> bool:
        normalized = self._normalize(path)
        if normalized in self._members:
            return True
        prefix = f"{normalized}/"
        return any(member.startswith(prefix) for member in self._members)

    def read_text(self, path: str) -> str | None:
        normalized = self._normalize(path)
        member = self._members.get(normalized)
        if member is None or self._handle is None or not member.isfile():
            return None
        extracted = self._handle.extractfile(member)
        if extracted is None:
            return None
        return extracted.read().decode("utf-8", errors="replace")

    def iter_texts(self, prefix: str) -> list[tuple[str, str]]:
        normalized_prefix = self._normalize(prefix).rstrip("/")
        items: list[tuple[str, str]] = []
        if self._handle is None:
            return items
        for member_path, member in self._members.items():
            if not member.isfile():
                continue
            if not member_path.startswith(f"{normalized_prefix}/"):
                continue
            extracted = self._handle.extractfile(member)
            if extracted is None:
                continue
            items.append((f"/{member_path}", extracted.read().decode("utf-8", errors="replace")))
        return items


def parse_docker_metadata(payload: list[dict[str, Any]]) -> DockerMetadata:
    if not payload or not isinstance(payload[0], dict):
        raise ContraceError("docker inspect payload is empty", ExitCode.RUNTIME_FAILURE)
    config = payload[0].get("Config") or {}
    if not isinstance(config, dict):
        raise ContraceError("docker inspect Config is missing", ExitCode.RUNTIME_FAILURE)

    env: dict[str, str] = {}
    for item in config.get("Env") or []:
        if not isinstance(item, str) or "=" not in item:
            continue
        key, value = item.split("=", 1)
        env[key] = value

    exposed_ports: list[int] = []
    raw_ports = config.get("ExposedPorts") or {}
    if isinstance(raw_ports, dict):
        for key in raw_ports:
            try:
                exposed_ports.append(int(str(key).split("/", 1)[0]))
            except ValueError:
                continue

    entrypoint = [str(item) for item in (config.get("Entrypoint") or [])]
    cmd = [str(item) for item in (config.get("Cmd") or [])]

    return DockerMetadata(
        user=str(config.get("User") or ""),
        workdir=str(config.get("WorkingDir") or ""),
        env=env,
        entrypoint=entrypoint,
        cmd=cmd,
        exposed_ports=sorted(set(exposed_ports)),
    )


def _parse_passwd(text: str | None) -> list[PasswdEntry]:
    if not text:
        return []
    entries: list[PasswdEntry] = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) != 7:
            continue
        entries.append(
            PasswdEntry(
                name=parts[0],
                uid=int(parts[2]),
                gid=int(parts[3]),
                gecos=parts[4],
                home=parts[5] or "/",
                shell=parts[6] or "/bin/sh",
            )
        )
    return entries


def _parse_group(text: str | None) -> list[GroupEntry]:
    if not text:
        return []
    entries: list[GroupEntry] = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) != 4:
            continue
        members = [member for member in parts[3].split(",") if member]
        entries.append(GroupEntry(name=parts[0], gid=int(parts[2]), members=members))
    return entries


def _lookup_passwd_by_name(entries: list[PasswdEntry], name: str) -> PasswdEntry | None:
    for entry in entries:
        if entry.name == name:
            return entry
    return None


def _lookup_passwd_by_uid(entries: list[PasswdEntry], uid: int) -> PasswdEntry | None:
    for entry in entries:
        if entry.uid == uid:
            return entry
    return None


def _lookup_group_by_name(entries: list[GroupEntry], name: str) -> GroupEntry | None:
    for entry in entries:
        if entry.name == name:
            return entry
    return None


def _lookup_group_by_gid(entries: list[GroupEntry], gid: int) -> GroupEntry | None:
    for entry in entries:
        if entry.gid == gid:
            return entry
    return None


def _resolve_user(
    user_spec: str,
    passwd_entries: list[PasswdEntry],
    group_entries: list[GroupEntry],
    allow_root_fallback: bool,
    warnings: list[str],
) -> tuple[int, int, list[int], str]:
    source = "docker inspect"
    if not user_spec:
        return 0, 0, [], source

    raw_user, _, raw_group = user_spec.partition(":")
    passwd_entry: PasswdEntry | None = None
    resolved_name: str | None = None

    try:
        uid = int(raw_user)
        passwd_entry = _lookup_passwd_by_uid(passwd_entries, uid)
        if passwd_entry is not None:
            resolved_name = passwd_entry.name
    except ValueError:
        passwd_entry = _lookup_passwd_by_name(passwd_entries, raw_user)
        if passwd_entry is None:
            if allow_root_fallback:
                warnings.append(f"USER '{user_spec}' not found; falling back to root")
                return 0, 0, [], "root fallback"
            raise ContraceError(f"unable to resolve user '{user_spec}'", ExitCode.RUNTIME_FAILURE)
        uid = passwd_entry.uid
        resolved_name = passwd_entry.name

    if raw_group:
        try:
            gid = int(raw_group)
            group_entry = _lookup_group_by_gid(group_entries, gid)
        except ValueError:
            group_entry = _lookup_group_by_name(group_entries, raw_group)
            if group_entry is None:
                if allow_root_fallback:
                    warnings.append(f"group '{raw_group}' not found; falling back to root")
                    return 0, 0, [], "root fallback"
                raise ContraceError(f"unable to resolve group '{raw_group}'", ExitCode.RUNTIME_FAILURE)
            gid = group_entry.gid
    else:
        if passwd_entry is not None:
            gid = passwd_entry.gid
        else:
            gid = uid

    supplementary: list[int] = []
    if resolved_name:
        for group in group_entries:
            if group.gid == gid:
                continue
            if resolved_name in group.members:
                supplementary.append(group.gid)

    return uid, gid, sorted(set(supplementary)), source


def _resolve_workdir(configured: str | None, metadata: DockerMetadata, fs: TarFilesystemView, warnings: list[str]) -> str:
    candidate = configured or metadata.workdir or "/"
    if fs.exists(candidate):
        return candidate
    if candidate != "/":
        warnings.append(f"workdir '{candidate}' does not exist in rootfs; falling back to /")
    return "/"


def _resolve_argv(config: ResolvedConfig, metadata: DockerMetadata) -> tuple[list[str], str]:
    if config.argv:
        return list(config.argv), "override"
    argv = [*metadata.entrypoint, *metadata.cmd]
    if not argv:
        raise ContraceError("no final argv could be resolved", ExitCode.RUNTIME_FAILURE)
    return argv, "docker inspect"


def _rewrite_socat_exec_target(argv: list[str], warnings: list[str]) -> tuple[list[str], str | None]:
    wrapper_path = "/usr/libexec/contrace-child-wrap"
    pattern = re.compile(r"EXEC:([^,\s]+)")

    if not argv:
        return argv, None

    if len(argv) >= 3 and PurePosixPath(argv[0]).name in {"sh", "bash"} and argv[1] == "-c":
        command = argv[2]
        match = pattern.search(command)
        if not match:
            return argv, None
        target = match.group(1)
        rewritten = command[: match.start(1)] + wrapper_path + command[match.end(1) :]
        warnings.append("rewrote socat EXEC target to capture child pid for attach watchdog")
        return [argv[0], argv[1], rewritten, *argv[3:]], target

    rewritten_argv: list[str] = []
    target: str | None = None
    for arg in argv:
        match = pattern.search(arg)
        if match and target is None:
            target = match.group(1)
            rewritten_argv.append(arg[: match.start(1)] + wrapper_path + arg[match.end(1) :])
        else:
            rewritten_argv.append(arg)
    if target is not None:
        warnings.append("rewrote socat EXEC target to capture child pid for attach watchdog")
    return rewritten_argv, target


def _resolve_ports(
    config: ResolvedConfig,
    metadata: DockerMetadata,
    fs: TarFilesystemView,
    argv: list[str],
    warnings: list[str],
) -> tuple[list[int], str]:
    if config.service_ports:
        return sorted(set(config.service_ports)), "config"
    if config.forwards:
        return sorted(set(item.guest for item in config.forwards)), "explicit forwards"
    if metadata.exposed_ports:
        return metadata.exposed_ports, "docker inspect"
    heuristic_ports: set[int] = set(infer_ports_from_argv(argv))
    if config.infer_ports:
        xinetd_ports = parse_xinetd_configs(fs.iter_texts("/etc/xinetd.d"))
        heuristic_ports.update(xinetd_ports)
        inetd_conf = fs.read_text("/etc/inetd.conf")
        if inetd_conf:
            heuristic_ports.update(parse_inetd_conf(inetd_conf))
    if heuristic_ports:
        warnings.append("service ports inferred heuristically")
        return sorted(heuristic_ports), "heuristic"
    warnings.append("no service ports detected")
    return [], "default"


def build_runtime_bundle(
    config: ResolvedConfig,
    inspect_payload: list[dict[str, Any]],
    rootfs_tar: str,
) -> RuntimeBundle:
    metadata = parse_docker_metadata(inspect_payload)

    with TarFilesystemView(rootfs_tar) as fs:
        warnings: list[str] = []
        passwd_entries = _parse_passwd(fs.read_text("/etc/passwd"))
        group_entries = _parse_group(fs.read_text("/etc/group"))

        argv, source_of_argv = _resolve_argv(config, metadata)
        manager = classify_manager(argv)
        socat_exec_target: str | None = None
        if manager == "socat":
            argv, socat_exec_target = _rewrite_socat_exec_target(argv, warnings)
        uid, gid, supplementary_gids, source_of_user = _resolve_user(
            config.runtime_user or metadata.user,
            passwd_entries,
            group_entries,
            config.allow_root_fallback,
            warnings,
        )
        workdir = _resolve_workdir(config.runtime_workdir, metadata, fs, warnings)
        service_ports, source_of_ports = _resolve_ports(config, metadata, fs, argv, warnings)

        if manager in {"socat", "xinetd", "inetd"} and config.enable_attach:
            warnings.append("attach watchdog is best-effort for fork-per-connection services")

        env = dict(metadata.env)
        env.update(config.env)
        env.setdefault("PATH", DEFAULT_PATH)
        env.setdefault("TERM", "xterm-256color")

        passwd_entry = _lookup_passwd_by_uid(passwd_entries, uid)
        if uid != 0:
            env.setdefault("HOME", passwd_entry.home if passwd_entry else "/")
        else:
            env.setdefault("HOME", "/root")

        shell_argv = config.shell_argv
        if config.shell_mode and not shell_argv:
            shell_argv = ["/bin/sh", "-c"]

    diagnostics = RuntimeDiagnostics(
        source_of_user=source_of_user,
        source_of_ports=source_of_ports,
        source_of_argv=source_of_argv,
        warnings=warnings,
    )
    spec = RuntimeSpec(
        guest_arch=config.guest_arch,
        env=env,
        workdir=workdir,
        uid=uid,
        gid=gid,
        supplementary_gids=supplementary_gids,
        argv=argv,
        shell_mode=config.shell_mode,
        shell_argv=shell_argv,
        manager=manager,
        service_ports=service_ports,
        debug_multi_port=config.gdb_multi_port,
        debug_attach_port=config.gdb_attach_port,
        trace_preset=config.trace_preset,
        hostname=config.hostname,
        keep_shell=config.keep_shell,
        socat_exec_target=socat_exec_target,
    )
    return RuntimeBundle(spec=spec, diagnostics=diagnostics)


def render_inspect_summary(bundle: RuntimeBundle) -> str:
    spec = bundle.spec
    diag = bundle.diagnostics
    ports = ", ".join(str(port) for port in spec.service_ports) or "(none)"
    warnings = "\n".join(f"  - {warning}" for warning in diag.warnings) if diag.warnings else "  - (none)"
    return "\n".join(
        [
            f"Guest arch:      {spec.guest_arch}",
            f"Manager:         {spec.manager}",
            f"Workdir:         {spec.workdir}",
            f"User:            uid={spec.uid} gid={spec.gid}",
            f"Ports:           service={ports}, gdb_multi={spec.debug_multi_port}, gdb_attach={spec.debug_attach_port}",
            f"Trace preset:    {spec.trace_preset}",
            "",
            "Final argv:",
            f"  {json.dumps(spec.argv)}",
            "",
            "Warnings:",
            warnings,
        ]
    )
