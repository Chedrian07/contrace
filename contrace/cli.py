from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any

from contrace.artifacts import ArtifactLayout
from contrace.config import CliOverrides, cli_overrides_from_args, load_file_config, resolve_config
from contrace.errors import ContraceError, ExitCode
from contrace.image import DockerImageBuilder
from contrace.intake import PreparedInput, prepare_input
from contrace.rootfs import assemble_rootfs
from contrace.runtime import RuntimeBundle, build_runtime_bundle, render_inspect_summary
from contrace.subprocess import CommandRunner
from contrace.vm import build_qemu_plan, run_qemu, write_qemu_command

LOGGER = logging.getLogger(__name__)

TOP_LEVEL_EPILOG = """Examples:
  contrace inspect ./challenge.zip --json
  contrace run ./challenge.zip
  contrace run ./challenge-dir --dry-run

Tips:
  - Subcommand help: `contrace run -h`
  - `contrace -h run` is also accepted and rewritten automatically
  - Default workdir: /tmp/contrace-*
  - Default trace preset: syscalls
"""

RUN_EPILOG = """Examples:
  contrace run ./challenge.zip
  contrace run ./challenge-dir --dry-run
  contrace run ./challenge.zip --disable-gdb-attach --no-shell
  contrace run ./challenge.zip --enable-gdb-attach --no-shell
"""

INSPECT_EPILOG = """Examples:
  contrace inspect ./challenge.zip
  contrace inspect ./challenge-dir --json
"""


def _normalize_help_argv(argv: list[str]) -> list[str]:
    if len(argv) == 2 and argv[0] in {"-h", "--help"} and argv[1] in {"run", "inspect"}:
        return [argv[1], argv[0]]
    return argv


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="contrace",
        description="Rehost a single-container Linux CTF challenge as an inspectable x86_64 QEMU guest.",
        epilog=TOP_LEVEL_EPILOG,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser(
        "run",
        help="build, export, assemble, and boot a guest",
        description="Build the image, normalize its runtime contract, assemble an initramfs guest, and boot QEMU.",
        epilog=RUN_EPILOG,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    inspect_parser = subparsers.add_parser(
        "inspect",
        help="show the resolved runtime contract without booting",
        description="Build/export the image and print the resolved runtime contract and diagnostics.",
        epilog=INSPECT_EPILOG,
        formatter_class=argparse.RawTextHelpFormatter,
    )

    for command_parser in (run_parser, inspect_parser):
        _add_common_arguments(command_parser)

    run_parser.add_argument("--dry-run", action="store_true")
    inspect_parser.add_argument("--json", action="store_true")
    return parser


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("path", help="path to a challenge directory, zip, or tar archive")
    parser.add_argument("--guest-arch", default=None, help="guest architecture override (default: x86_64)")
    parser.add_argument("--memory", "-m", default=None, help="guest memory override (default: 512M)")
    parser.add_argument("--cpus", type=int, default=None, help="guest vCPU count override (default: 1)")
    parser.add_argument("--workdir", default=None, help="artifact workdir override (default: /tmp/contrace-*)")
    parser.add_argument("--keep-workdir", action="store_true", help="preserve the artifact workdir after completion")
    parser.add_argument("--config", default=None, help="explicit path to contrace.yml")
    parser.add_argument("--port", action="append", help="explicit host:guest forward, repeatable")
    parser.add_argument("--trace", default=None, help="trace preset override (default: syscalls)")
    parser.add_argument("--env", action="append", help="runtime env override KEY=VALUE, repeatable")
    parser.add_argument("--user", default=None, help="runtime user override, e.g. chall or chall:chall")
    parser.add_argument("--argv", default=None, help="final argv override as a JSON array of strings")
    parser.add_argument("--shell-mode", action="store_true", default=None, help="force shell execution mode")
    parser.add_argument("--hostname", default=None, help="guest hostname override")
    parser.add_argument("--gdb-multi-port", type=int, default=None, help="host port for gdbserver --multi (default: 1234)")
    parser.add_argument("--gdb-attach-port", type=int, default=None, help="host port for gdbserver --attach (default: 1235)")
    attach_group = parser.add_mutually_exclusive_group()
    attach_group.add_argument("--enable-gdb-attach", action="store_true", help="enable best-effort attach watchdog")
    attach_group.add_argument("--disable-gdb-attach", action="store_true", help="disable attach watchdog")
    parser.add_argument("--qemu-gdb-port", type=int, default=None, help="enable QEMU gdbstub on the given host port")
    parser.add_argument("--no-shell", dest="keep_shell", action="store_false", default=None, help="do not leave a serial root shell open")
    parser.add_argument("--allow-root-fallback", action="store_true", help="fall back to root if USER resolution fails")
    parser.add_argument("--verbose", "-v", action="count", default=0, help="increase logging verbosity")


def configure_logging(verbosity: int) -> None:
    level = logging.DEBUG if verbosity > 0 else logging.INFO
    logging.basicConfig(level=level, format="[%(levelname)s] %(message)s")


def _resolve_config_path(prepared: PreparedInput, overrides: CliOverrides) -> Path | None:
    if overrides.explicit_config is not None:
        return overrides.explicit_config.expanduser().resolve()
    return prepared.detected_config_path


def _prepare_context(args: argparse.Namespace) -> tuple[ArtifactLayout, PreparedInput, CliOverrides, Any, Path | None]:
    overrides = cli_overrides_from_args(args)
    configure_logging(overrides.verbose)
    layout = ArtifactLayout.create(overrides.host_workdir, overrides.keep_workdir)
    prepared = prepare_input(Path(args.path), layout)
    config_path = _resolve_config_path(prepared, overrides)
    file_config = load_file_config(config_path)
    resolved = resolve_config(file_config, overrides)
    return layout, prepared, overrides, resolved, config_path


def _write_runtime_artifact(layout: ArtifactLayout, bundle: RuntimeBundle) -> None:
    layout.write_json(layout.runtime_json, bundle.spec.to_dict())


def _build_output_payload(
    layout: ArtifactLayout,
    prepared: PreparedInput,
    config_path: Path | None,
    bundle: RuntimeBundle,
    *,
    qemu_command: list[str] | None = None,
    forwards: list[dict[str, int]] | None = None,
    accel: dict[str, str] | None = None,
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    payload = {
        "input": prepared.to_dict(),
        "config_path": str(config_path) if config_path else None,
        "runtime": bundle.spec.to_dict(),
        "diagnostics": bundle.diagnostics.to_dict(),
        "artifacts": {
            "workdir": str(layout.root),
            "inspect_json": str(layout.inspect_json),
            "runtime_json": str(layout.runtime_json),
            "rootfs_tar": str(layout.rootfs_tar),
            "rootfs_cpio_gz": str(layout.initramfs_path),
            "qemu_cmd": str(layout.qemu_cmd),
            "serial_log": str(layout.serial_log),
        },
    }
    if qemu_command is not None:
        payload["qemu_command"] = qemu_command
    if forwards is not None:
        payload["forwards"] = forwards
    if accel is not None:
        payload["accelerator"] = accel
    if warnings:
        payload["warnings"] = warnings
    return payload


def handle_inspect(args: argparse.Namespace) -> int:
    layout: ArtifactLayout | None = None
    try:
        layout, prepared, _, resolved, config_path = _prepare_context(args)
        runner = CommandRunner()
        image = DockerImageBuilder(runner).build_and_export(prepared, resolved.guest_arch, layout)
        bundle = build_runtime_bundle(resolved, image.inspect_payload, str(image.rootfs_tar))
        _write_runtime_artifact(layout, bundle)
        payload = _build_output_payload(layout, prepared, config_path, bundle)

        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(render_inspect_summary(bundle))
            print(f"\nArtifacts:\n  {layout.root}")
        return int(ExitCode.SUCCESS)
    finally:
        if layout is not None:
            layout.cleanup()


def handle_run(args: argparse.Namespace) -> int:
    layout: ArtifactLayout | None = None
    try:
        layout, prepared, _, resolved, config_path = _prepare_context(args)
        runner = CommandRunner()
        image = DockerImageBuilder(runner).build_and_export(prepared, resolved.guest_arch, layout)
        bundle = build_runtime_bundle(resolved, image.inspect_payload, str(image.rootfs_tar))
        _write_runtime_artifact(layout, bundle)
        assembly = assemble_rootfs(layout, bundle)
        plan = build_qemu_plan(layout, resolved, bundle)
        write_qemu_command(layout, plan)

        print(render_inspect_summary(bundle))
        print(f"\nWorkdir:         {layout.root}")
        print(f"Initramfs:       {assembly.initramfs_path}")
        print(f"Kernel:          {plan.kernel_path}")
        print(f"Accelerator:     {plan.accel.accel} ({plan.accel.reason})")
        if plan.forwards:
            print("Forwards:")
            for mapping in plan.forwards:
                print(f"  - 127.0.0.1:{mapping.host} -> guest:{mapping.guest}")
        if assembly.warnings:
            print("Assembly warnings:")
            for warning in assembly.warnings:
                print(f"  - {warning}")
        if args.dry_run:
            LOGGER.info("dry-run requested; skipping QEMU boot")
            return int(ExitCode.SUCCESS)

        run_qemu(runner, plan, layout)
        return int(ExitCode.SUCCESS)
    finally:
        if layout is not None:
            layout.cleanup()


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    argv = _normalize_help_argv(list(argv))
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect":
            return handle_inspect(args)
        if args.command == "run":
            return handle_run(args)
        parser.error(f"unsupported command: {args.command}")
        return int(ExitCode.INVALID_INPUT)
    except ContraceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return int(exc.exit_code)
