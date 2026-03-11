from __future__ import annotations

import gzip
import logging
import os
import shutil
import stat
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from contrace.artifacts import ArtifactLayout
from contrace.errors import ContraceError, ExitCode
from contrace.init_gen import render_init_script, render_watchdog_script
from contrace.paths import static_tool_path
from contrace.runtime import RuntimeBundle

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class FileMetadata:
    mode: int
    uid: int
    gid: int
    mtime: int


@dataclass(slots=True)
class ToolResolution:
    guest_path: str
    source_path: Path | None
    required: bool
    injected: bool


@dataclass(slots=True)
class RootfsAssembly:
    guest_root_dir: Path
    initramfs_path: Path
    warnings: list[str]


def _normalize(path: str) -> str:
    return str(PurePosixPath(path)).lstrip("/")


def _safe_extract_tar(archive: Path, destination: Path) -> dict[str, FileMetadata]:
    metadata: dict[str, FileMetadata] = {}
    dest_root = destination.resolve()
    with tarfile.open(archive) as handle:
        members = handle.getmembers()
        extracted_files: dict[str, Path] = {}
        for member in members:
            normalized = _normalize(member.name)
            if normalized in {"", "."}:
                metadata["."] = FileMetadata(
                    mode=member.mode or 0o755,
                    uid=member.uid,
                    gid=member.gid,
                    mtime=int(member.mtime),
                )
                continue
            member_path = destination / normalized
            try:
                member_path.parent.resolve().relative_to(dest_root)
            except ValueError as exc:
                raise ContraceError(
                    f"archive contains unsafe path: {member.name}",
                    ExitCode.GUEST_ASSEMBLY_FAILURE,
                ) from exc
            metadata[normalized] = FileMetadata(
                mode=member.mode,
                uid=member.uid,
                gid=member.gid,
                mtime=int(member.mtime),
            )
        for member in members:
            normalized = _normalize(member.name)
            if normalized in {"", "."}:
                continue
            target = destination / normalized
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if member.issym():
                if target.exists() or target.is_symlink():
                    target.unlink()
                os.symlink(member.linkname, target)
                continue
            if member.islnk():
                link_target = extracted_files.get(_normalize(member.linkname))
                if link_target is None:
                    raise ContraceError(
                        f"hardlink target missing in archive: {member.linkname}",
                        ExitCode.GUEST_ASSEMBLY_FAILURE,
                    )
                if target.exists():
                    target.unlink()
                os.link(link_target, target)
                extracted_files[normalized] = target
                continue
            extracted = handle.extractfile(member)
            if extracted is None:
                continue
            with target.open("wb") as out_handle:
                shutil.copyfileobj(extracted, out_handle)
            os.chmod(target, member.mode)
            extracted_files[normalized] = target
    return metadata


def _ensure_directory(path: Path, metadata_map: dict[str, FileMetadata]) -> None:
    path.mkdir(parents=True, exist_ok=True)
    metadata_map.setdefault(_normalize(str(path.relative_to(path.anchor or "/"))), FileMetadata(0o755, 0, 0, 0))


def _tool_candidates(name: str) -> list[str]:
    if name == "busybox":
        return ["/bin/busybox", "/usr/bin/busybox"]
    if name == "gdbserver":
        return ["/usr/bin/gdbserver", "/bin/gdbserver"]
    if name == "trace-cmd":
        return ["/usr/bin/trace-cmd", "/bin/trace-cmd"]
    if name == "contrace-exec":
        return ["/usr/libexec/contrace-exec"]
    if name == "contrace-child-wrap":
        return ["/usr/libexec/contrace-child-wrap"]
    raise ValueError(name)


def _resolve_tool(
    guest_root: Path,
    guest_arch: str,
    name: str,
    required: bool,
    metadata_map: dict[str, FileMetadata],
) -> ToolResolution:
    for candidate in _tool_candidates(name):
        candidate_path = guest_root / candidate.lstrip("/")
        if candidate_path.exists():
            return ToolResolution(candidate, None, required, False)

    static_path = static_tool_path(guest_arch, name)
    if static_path.exists():
        target = Path(_tool_candidates(name)[0].lstrip("/"))
        target_path = guest_root / target
        target_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(static_path, target_path)
        target_path.chmod(0o755)
        metadata_map[_normalize(str(target))] = FileMetadata(0o755, 0, 0, 0)
        return ToolResolution(f"/{target}", static_path, required, True)

    if required:
        raise ContraceError(
            f"required guest tool '{name}' is missing; provide it in static/{guest_arch}/{name} or in the image rootfs",
            ExitCode.GUEST_ASSEMBLY_FAILURE,
        )
    return ToolResolution(_tool_candidates(name)[0], None, required, False)


def _write_text(path: Path, content: str, metadata_map: dict[str, FileMetadata], executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    mode = 0o755 if executable else 0o644
    path.chmod(mode)
    metadata_map[_normalize(str(path.relative_to(path.parents[len(path.parents) - 1] if path.is_absolute() else Path("."))))] = FileMetadata(mode, 0, 0, 0)


def _walk_entries(root: Path) -> list[Path]:
    entries = [root]
    entries.extend(sorted(root.rglob("*")))
    return entries


def _cpio_pad(handle: Any, size: int) -> None:
    remainder = size % 4
    if remainder:
        handle.write(b"\x00" * (4 - remainder))


def _write_cpio_entry(handle: Any, relpath: str, path: Path, metadata: FileMetadata) -> None:
    st = os.lstat(path)
    if stat.S_ISDIR(st.st_mode):
        data = b""
        mode = stat.S_IFDIR | metadata.mode
        nlink = 2
    elif stat.S_ISLNK(st.st_mode):
        data = os.readlink(path).encode("utf-8")
        mode = stat.S_IFLNK | metadata.mode
        nlink = 1
    else:
        data = path.read_bytes()
        mode = stat.S_IFREG | metadata.mode
        nlink = 1

    namesize = len(relpath.encode("utf-8")) + 1
    header = (
        "070701"
        f"{0:08x}"
        f"{mode:08x}"
        f"{metadata.uid:08x}"
        f"{metadata.gid:08x}"
        f"{nlink:08x}"
        f"{metadata.mtime:08x}"
        f"{len(data):08x}"
        f"{0:08x}{0:08x}{0:08x}{0:08x}"
        f"{namesize:08x}"
        f"{0:08x}"
    )
    handle.write(header.encode("ascii"))
    handle.write(relpath.encode("utf-8") + b"\x00")
    _cpio_pad(handle, 110 + namesize)
    if data:
        handle.write(data)
    _cpio_pad(handle, len(data))


def _pack_initramfs(root: Path, output_path: Path, metadata_map: dict[str, FileMetadata]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(output_path, "wb") as gz_handle:
        for path in _walk_entries(root):
            rel = "." if path == root else str(path.relative_to(root))
            if rel == ".":
                continue
            metadata = metadata_map.get(_normalize(rel), FileMetadata(path.lstat().st_mode & 0o7777, 0, 0, 0))
            _write_cpio_entry(gz_handle, rel, path, metadata)
        trailer_path = root / ".contrace-trailer"
        trailer_path.write_text("", encoding="utf-8")
        try:
            _write_cpio_entry(gz_handle, "TRAILER!!!", trailer_path, FileMetadata(0o000, 0, 0, 0))
        finally:
            trailer_path.unlink(missing_ok=True)


def assemble_rootfs(layout: ArtifactLayout, bundle: RuntimeBundle) -> RootfsAssembly:
    if layout.guest_root_dir.exists():
        shutil.rmtree(layout.guest_root_dir)
    layout.guest_root_dir.mkdir(parents=True, exist_ok=True)
    metadata_map = _safe_extract_tar(layout.rootfs_tar, layout.guest_root_dir)
    warnings: list[str] = []

    busybox = _resolve_tool(layout.guest_root_dir, bundle.spec.guest_arch, "busybox", True, metadata_map)
    gdbserver = _resolve_tool(layout.guest_root_dir, bundle.spec.guest_arch, "gdbserver", True, metadata_map)
    trace_cmd = _resolve_tool(layout.guest_root_dir, bundle.spec.guest_arch, "trace-cmd", False, metadata_map)

    helper_needed = bool(bundle.spec.uid or bundle.spec.gid or bundle.spec.supplementary_gids)
    helper_path: str | None = None
    try:
        helper = _resolve_tool(layout.guest_root_dir, bundle.spec.guest_arch, "contrace-exec", helper_needed, metadata_map)
        helper_path = helper.guest_path if helper.source_path or (layout.guest_root_dir / helper.guest_path.lstrip("/")).exists() else None
    except ContraceError:
        if helper_needed:
            raise
        helper_path = None

    if bundle.spec.socat_exec_target:
        _resolve_tool(layout.guest_root_dir, bundle.spec.guest_arch, "contrace-child-wrap", True, metadata_map)

    if trace_cmd.source_path is None and not (layout.guest_root_dir / trace_cmd.guest_path.lstrip("/")).exists():
        warnings.append("trace-cmd is not present in the guest; trace presets still work via tracefs")

    runtime_dir = layout.guest_root_dir / "etc" / "contrace"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    runtime_json_path = runtime_dir / "runtime.json"
    runtime_json_path.write_text(
        __import__("json").dumps(bundle.spec.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    metadata_map["etc/contrace/runtime.json"] = FileMetadata(0o644, 0, 0, 0)

    watchdog_path = layout.guest_root_dir / "usr" / "libexec" / "contrace-watchdog.sh"
    watchdog_path.parent.mkdir(parents=True, exist_ok=True)
    watchdog_path.write_text(render_watchdog_script(), encoding="utf-8")
    watchdog_path.chmod(0o755)
    metadata_map["usr/libexec/contrace-watchdog.sh"] = FileMetadata(0o755, 0, 0, 0)

    init_content = render_init_script(
        bundle.spec,
        busybox_path=busybox.guest_path,
        helper_path=helper_path,
        direct_exec_ok=not helper_needed,
    )
    layout.init_path.write_text(init_content, encoding="utf-8")
    layout.init_path.chmod(0o755)
    metadata_map["init"] = FileMetadata(0o755, 0, 0, 0)

    _pack_initramfs(layout.guest_root_dir, layout.initramfs_path, metadata_map)
    return RootfsAssembly(
        guest_root_dir=layout.guest_root_dir,
        initramfs_path=layout.initramfs_path,
        warnings=warnings,
    )
