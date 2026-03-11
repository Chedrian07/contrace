from pathlib import Path

import pytest

from contrace.config import ForwardMapping, ResolvedConfig
from contrace.errors import ContraceError
from contrace.runtime import RuntimeBundle, RuntimeDiagnostics, RuntimeSpec
from contrace.vm import build_accel_argument, build_forward_mappings, select_accelerator


def _bundle() -> RuntimeBundle:
    return RuntimeBundle(
        spec=RuntimeSpec(
            guest_arch="x86_64",
            env={},
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
        ),
        diagnostics=RuntimeDiagnostics("docker inspect", "docker inspect", "docker inspect", []),
    )


def test_select_accelerator_matches_macos_cross_arch(monkeypatch) -> None:
    monkeypatch.setattr("platform.system", lambda: "Darwin")
    monkeypatch.setattr("platform.machine", lambda: "arm64")

    selection = select_accelerator("x86_64")

    assert selection.accel == "tcg"
    assert build_accel_argument(selection) == "tcg,thread=multi,tb-size=512"


def test_build_forward_mappings_rejects_duplicate_host_port(monkeypatch) -> None:
    monkeypatch.setattr("contrace.vm._validate_port_free", lambda port: None)
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
        env={},
        service_ports=[],
        forwards=[ForwardMapping(host=1234, guest=31337)],
        trace_preset="off",
        gdb_multi_port=1234,
        gdb_attach_port=1235,
        enable_attach=True,
        qemu_gdb_port=None,
        allow_root_fallback=False,
        keep_shell=True,
        infer_ports=True,
    )

    with pytest.raises(ContraceError):
        build_forward_mappings(config, _bundle())
