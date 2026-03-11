from pathlib import Path

import pytest

from contrace.cli import _normalize_help_argv, main
from contrace.runtime import RuntimeBundle, RuntimeDiagnostics, RuntimeSpec


class FakeImage:
    inspect_payload = [{"Config": {}}]
    rootfs_tar = Path("/tmp/fake-rootfs.tar")


def _fake_bundle() -> RuntimeBundle:
    return RuntimeBundle(
        spec=RuntimeSpec(
            guest_arch="x86_64",
            env={"TERM": "xterm-256color"},
            workdir="/",
            uid=0,
            gid=0,
            supplementary_gids=[],
            argv=["/bin/echo", "hello"],
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
        diagnostics=RuntimeDiagnostics(
            source_of_user="docker inspect",
            source_of_ports="docker inspect",
            source_of_argv="docker inspect",
            warnings=[],
        ),
    )


def test_inspect_json_writes_runtime_artifact(tmp_path: Path, capsys, monkeypatch) -> None:
    source = tmp_path / "challenge"
    source.mkdir()
    (source / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")

    monkeypatch.setattr(
        "contrace.cli.DockerImageBuilder.build_and_export",
        lambda self, prepared, guest_arch, layout: FakeImage(),
    )
    monkeypatch.setattr("contrace.cli.build_runtime_bundle", lambda resolved, payload, rootfs: _fake_bundle())

    workdir = tmp_path / "workdir"
    exit_code = main(
        [
            "inspect",
            str(source),
            "--json",
            "--keep-workdir",
            "--workdir",
            str(workdir),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"runtime"' in captured.out
    assert (workdir / "generated" / "runtime.json").exists()


def test_normalize_help_argv_rewrites_subcommand_help() -> None:
    assert _normalize_help_argv(["-h", "run"]) == ["run", "-h"]
    assert _normalize_help_argv(["--help", "inspect"]) == ["inspect", "--help"]


def test_top_level_help_mentions_examples(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["-h"])

    captured = capsys.readouterr()
    assert exc.value.code == 0
    assert "Examples:" in captured.out
    assert "contrace run ./challenge.zip" in captured.out
