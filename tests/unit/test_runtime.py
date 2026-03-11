import tarfile
from pathlib import Path

from contrace.config import ForwardMapping, ResolvedConfig
from contrace.runtime import build_runtime_bundle


def _write_rootfs_tar(path: Path) -> None:
    root = path.parent / "rootfs"
    (root / "etc").mkdir(parents=True)
    (root / "home" / "ctf").mkdir(parents=True)
    (root / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/sh\nctf:x:1000:1000::/home/ctf:/bin/sh\n",
        encoding="utf-8",
    )
    (root / "etc" / "group").write_text(
        "root:x:0:\nctf:x:1000:ctf\ntrace:x:1001:ctf\n",
        encoding="utf-8",
    )
    with tarfile.open(path, "w") as handle:
        handle.add(root, arcname=".")


def test_build_runtime_bundle_resolves_user_and_ports(tmp_path: Path) -> None:
    rootfs_tar = tmp_path / "rootfs.tar"
    _write_rootfs_tar(rootfs_tar)

    config = ResolvedConfig(
        guest_arch="x86_64",
        memory="512M",
        cpus=1,
        hostname="contrace",
        runtime_user=None,
        runtime_workdir=None,
        argv=None,
        shell_mode=False,
        shell_argv=None,
        env={"FLAG": "flag{test}"},
        service_ports=[],
        forwards=[],
        trace_preset="off",
        gdb_multi_port=1234,
        gdb_attach_port=1235,
        enable_attach=True,
        qemu_gdb_port=None,
        allow_root_fallback=False,
        keep_shell=True,
        infer_ports=True,
    )
    inspect_payload = [
        {
            "Config": {
                "User": "ctf",
                "WorkingDir": "/home/ctf",
                "Env": ["PATH=/usr/bin", "TERM=screen"],
                "Entrypoint": ["socat"],
                "Cmd": ["TCP-LISTEN:31337,reuseaddr,fork", "EXEC:/home/ctf/chall"],
                "ExposedPorts": {"31337/tcp": {}},
            }
        }
    ]

    bundle = build_runtime_bundle(config, inspect_payload, str(rootfs_tar))

    assert bundle.spec.uid == 1000
    assert bundle.spec.gid == 1000
    assert bundle.spec.supplementary_gids == [1001]
    assert bundle.spec.workdir == "/home/ctf"
    assert bundle.spec.service_ports == [31337]
    assert bundle.spec.env["FLAG"] == "flag{test}"
    assert bundle.spec.env["HOME"] == "/home/ctf"
    assert bundle.spec.manager == "socat"
    assert bundle.diagnostics.source_of_argv == "docker inspect"
    assert bundle.diagnostics.source_of_ports == "docker inspect"
