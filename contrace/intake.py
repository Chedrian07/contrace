from __future__ import annotations

import shutil
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from contrace.artifacts import ArtifactLayout
from contrace.errors import ContraceError, ExitCode


@dataclass(slots=True)
class PreparedInput:
    original_path: Path
    staging_root: Path
    source_root: Path
    dockerfile_path: Path
    detected_config_path: Path | None
    extracted: bool

    def to_dict(self) -> dict[str, str | bool | None]:
        return {
            "original_path": str(self.original_path),
            "staging_root": str(self.staging_root),
            "source_root": str(self.source_root),
            "dockerfile_path": str(self.dockerfile_path),
            "detected_config_path": str(self.detected_config_path) if self.detected_config_path else None,
            "extracted": self.extracted,
        }


def _safe_extract_tar(archive: Path, destination: Path) -> None:
    with tarfile.open(archive) as handle:
        for member in handle.getmembers():
            member_path = destination / member.name
            try:
                member_path.resolve().relative_to(destination.resolve())
            except ValueError as exc:
                raise ContraceError(
                    f"archive contains unsafe path: {member.name}",
                    ExitCode.INVALID_INPUT,
                ) from exc
        handle.extractall(destination, filter="data")


def _safe_extract_zip(archive: Path, destination: Path) -> None:
    dest_root = destination.resolve()
    with zipfile.ZipFile(archive) as handle:
        for member in handle.infolist():
            member_path = destination / member.filename
            try:
                member_path.resolve().relative_to(dest_root)
            except ValueError as exc:
                raise ContraceError(
                    f"archive contains unsafe path: {member.filename}",
                    ExitCode.INVALID_INPUT,
                ) from exc
        handle.extractall(destination)


def _find_source_root(staging_root: Path) -> Path:
    if (staging_root / "Dockerfile").is_file():
        return staging_root

    dockerfiles = sorted(staging_root.rglob("Dockerfile"))
    if not dockerfiles:
        raise ContraceError("Dockerfile not found in input", ExitCode.INVALID_INPUT)
    if len(dockerfiles) > 1:
        joined = ", ".join(str(path.relative_to(staging_root)) for path in dockerfiles)
        raise ContraceError(
            f"multiple Dockerfile candidates found; disambiguate input root: {joined}",
            ExitCode.INVALID_INPUT,
        )
    return dockerfiles[0].parent


def prepare_input(input_path: Path, layout: ArtifactLayout) -> PreparedInput:
    source_path = input_path.expanduser().resolve()
    if not source_path.exists():
        raise ContraceError(f"input path not found: {source_path}", ExitCode.INVALID_INPUT)

    staging_root = layout.source_dir
    extracted = False

    if source_path.is_dir():
        if any(staging_root.iterdir()):
            raise ContraceError(
                f"staging directory is not empty: {staging_root}",
                ExitCode.INVALID_INPUT,
            )
        shutil.copytree(source_path, staging_root, dirs_exist_ok=True)
    elif tarfile.is_tarfile(source_path):
        extracted = True
        _safe_extract_tar(source_path, staging_root)
    elif zipfile.is_zipfile(source_path):
        extracted = True
        _safe_extract_zip(source_path, staging_root)
    else:
        raise ContraceError(
            "input must be a directory, zip archive, or tar-compatible archive",
            ExitCode.INVALID_INPUT,
        )

    source_root = _find_source_root(staging_root)
    config_path = source_root / "contrace.yml"
    return PreparedInput(
        original_path=source_path,
        staging_root=staging_root,
        source_root=source_root,
        dockerfile_path=source_root / "Dockerfile",
        detected_config_path=config_path if config_path.exists() else None,
        extracted=extracted,
    )
