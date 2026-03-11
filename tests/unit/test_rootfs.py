import tarfile
from pathlib import Path

from contrace.artifacts import ArtifactLayout
from contrace.rootfs import assemble_rootfs
from contrace.runtime import RuntimeBundle, RuntimeDiagnostics, RuntimeSpec


def _make_rootfs_tar(path: Path) -> None:
    root = path.parent / "image-root"
    (root / "etc").mkdir(parents=True)
    (root / "bin").mkdir(parents=True)
    (root / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\n", encoding="utf-8")
    (root / "etc" / "group").write_text("root:x:0:\n", encoding="utf-8")
    with tarfile.open(path, "w") as handle:
        handle.add(root, arcname=".")


def _bundle() -> RuntimeBundle:
    return RuntimeBundle(
        spec=RuntimeSpec(
            guest_arch="x86_64",
            env={"TERM": "xterm-256color"},
            workdir="/",
            uid=0,
            gid=0,
            supplementary_gids=[],
            argv=["/bin/chall"],
            shell_mode=False,
            shell_argv=None,
            manager="direct",
            service_ports=[31337],
            debug_multi_port=1234,
            debug_attach_port=1235,
            trace_preset="off",
            hostname="contrace",
            keep_shell=True,
            socat_exec_target=None,
        ),
        diagnostics=RuntimeDiagnostics(
            source_of_user="docker inspect",
            source_of_ports="docker inspect",
            source_of_argv="docker inspect",
            warnings=[],
        ),
    )


def test_assemble_rootfs_creates_initramfs(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    static_dir = tmp_path / "static" / "x86_64"
    static_dir.mkdir(parents=True)
    for name in ("busybox", "gdbserver", "trace-cmd"):
        path = static_dir / name
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o755)

    layout = ArtifactLayout.create(tmp_path / "workdir", keep_workdir=True)
    _make_rootfs_tar(layout.rootfs_tar)
    assembly = assemble_rootfs(layout, _bundle())

    assert assembly.initramfs_path.exists()
    assert (layout.guest_root_dir / "init").exists()
    assert (layout.guest_root_dir / "etc" / "contrace" / "runtime.json").exists()
    assert (layout.guest_root_dir / "usr" / "sbin" / "poweroff").is_symlink()
