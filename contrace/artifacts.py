from __future__ import annotations

import json
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from contrace.errors import ContraceError, ExitCode


@dataclass(slots=True)
class ArtifactLayout:
    root: Path
    source_dir: Path
    generated_dir: Path
    logs_dir: Path
    keep_workdir: bool
    owns_root: bool

    @property
    def inspect_json(self) -> Path:
        return self.generated_dir / "inspect.json"

    @property
    def build_log(self) -> Path:
        return self.logs_dir / "build.log"

    @property
    def runtime_json(self) -> Path:
        return self.generated_dir / "runtime.json"

    @property
    def rootfs_tar(self) -> Path:
        return self.generated_dir / "rootfs.tar"

    @property
    def guest_root_dir(self) -> Path:
        return self.root / "guest-root"

    @property
    def init_path(self) -> Path:
        return self.guest_root_dir / "init"

    @property
    def initramfs_path(self) -> Path:
        return self.generated_dir / "rootfs.cpio.gz"

    @property
    def qemu_cmd(self) -> Path:
        return self.generated_dir / "qemu.cmd"

    @property
    def serial_log(self) -> Path:
        return self.logs_dir / "serial.log"

    @classmethod
    def create(cls, workdir: Path | None, keep_workdir: bool) -> "ArtifactLayout":
        if workdir is None:
            root = Path(tempfile.mkdtemp(prefix="contrace-", dir="/tmp"))
            owns_root = True
        else:
            root = workdir.expanduser().resolve()
            owns_root = True
            if root.exists() and any(root.iterdir()):
                raise ContraceError(
                    f"work directory already exists and is not empty: {root}",
                    ExitCode.INVALID_INPUT,
                )
            root.mkdir(parents=True, exist_ok=True)

        source_dir = root / "source"
        generated_dir = root / "generated"
        logs_dir = root / "logs"
        source_dir.mkdir(parents=True, exist_ok=True)
        generated_dir.mkdir(parents=True, exist_ok=True)
        logs_dir.mkdir(parents=True, exist_ok=True)
        return cls(
            root=root,
            source_dir=source_dir,
            generated_dir=generated_dir,
            logs_dir=logs_dir,
            keep_workdir=keep_workdir,
            owns_root=owns_root,
        )

    def write_json(self, path: Path, payload: dict[str, Any]) -> None:
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def cleanup(self) -> None:
        if self.keep_workdir:
            return
        if self.owns_root and self.root.exists():
            shutil.rmtree(self.root)
