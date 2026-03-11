from __future__ import annotations

import logging
import platform
import shlex
import socket
from dataclasses import dataclass
from pathlib import Path

from contrace.artifacts import ArtifactLayout
from contrace.config import ForwardMapping, ResolvedConfig
from contrace.errors import ContraceError, ExitCode
from contrace.paths import kernel_artifact_hint_path, kernel_artifact_path
from contrace.runtime import RuntimeBundle
from contrace.subprocess import CommandRunner

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class AccelSelection:
    accel: str
    reason: str


def build_accel_argument(selection: AccelSelection) -> str:
    if selection.accel == "tcg":
        return "tcg,thread=multi,tb-size=512"
    return selection.accel


@dataclass(slots=True)
class QemuPlan:
    command: list[str]
    forwards: list[ForwardMapping]
    accel: AccelSelection
    kernel_path: Path


def select_accelerator(guest_arch: str) -> AccelSelection:
    host_system = platform.system()
    host_arch = platform.machine().lower()
    if host_system == "Linux" and host_arch in {"x86_64", "amd64"} and guest_arch == "x86_64":
        kvm = Path("/dev/kvm")
        if kvm.exists():
            return AccelSelection("kvm", "same-arch Linux host with /dev/kvm available")
        return AccelSelection("tcg", "same-arch Linux host but /dev/kvm is unavailable")
    if host_system == "Darwin":
        if host_arch in {"x86_64", "amd64"} and guest_arch == "x86_64":
            return AccelSelection("hvf", "same-arch macOS host supports HVF")
        return AccelSelection("tcg", "macOS cross-arch execution uses TCG-first path")
    return AccelSelection("tcg", "portable fallback path")


def _validate_port_free(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError as exc:
            raise ContraceError(f"host port {port} is already in use", ExitCode.QEMU_FAILURE) from exc


def build_forward_mappings(config: ResolvedConfig, bundle: RuntimeBundle) -> list[ForwardMapping]:
    if config.forwards:
        forwards = list(config.forwards)
    else:
        forwards = [ForwardMapping(host=port, guest=port) for port in bundle.spec.service_ports]
    forwards.extend(
        [
            ForwardMapping(host=bundle.spec.debug_multi_port, guest=bundle.spec.debug_multi_port),
        ]
    )
    if config.enable_attach:
        forwards.append(ForwardMapping(host=bundle.spec.debug_attach_port, guest=bundle.spec.debug_attach_port))

    deduped: dict[tuple[int, int], ForwardMapping] = {}
    used_hosts: set[int] = set()
    for item in forwards:
        if item.host in used_hosts:
            raise ContraceError(f"duplicate host port mapping detected: {item.host}", ExitCode.QEMU_FAILURE)
        used_hosts.add(item.host)
        deduped[(item.host, item.guest)] = item
        _validate_port_free(item.host)
    return list(deduped.values())


def resolve_kernel_path(guest_arch: str) -> Path:
    kernel_path = kernel_artifact_path(guest_arch)
    if kernel_path.exists():
        return kernel_path
    artifact_hint = kernel_artifact_hint_path(guest_arch)
    if artifact_hint.exists():
        raise ContraceError(
            f"kernel artifact missing at {kernel_path}. Fetch it first with scripts/fetch-kernel.sh",
            ExitCode.QEMU_FAILURE,
        )
    raise ContraceError(f"kernel artifact missing at {kernel_path}", ExitCode.QEMU_FAILURE)


def build_qemu_plan(layout: ArtifactLayout, config: ResolvedConfig, bundle: RuntimeBundle) -> QemuPlan:
    kernel_path = resolve_kernel_path(bundle.spec.guest_arch)
    forwards = build_forward_mappings(config, bundle)
    accel = select_accelerator(bundle.spec.guest_arch)

    hostfwd_parts = [f"hostfwd=tcp::{item.host}-:{item.guest}" for item in forwards]
    netdev = ",".join(["user", "id=net0", *hostfwd_parts])
    command = [
        "qemu-system-x86_64",
        "-accel",
        build_accel_argument(accel),
        "-kernel",
        str(kernel_path),
        "-initrd",
        str(layout.initramfs_path),
        "-append",
        "console=ttyS0 rdinit=/init loglevel=6 panic=-1 printk.time=1",
        "-nographic",
        "-m",
        config.memory,
        "-smp",
        str(config.cpus),
        "-netdev",
        netdev,
        "-device",
        "virtio-net-pci,netdev=net0",
        "-chardev",
        f"stdio,id=char0,signal=off,logfile={layout.serial_log},logappend=off",
        "-serial",
        "chardev:char0",
        "-monitor",
        "none",
    ]
    if config.qemu_gdb_port is not None:
        _validate_port_free(config.qemu_gdb_port)
        command.extend(["-gdb", f"tcp::{config.qemu_gdb_port}"])
    return QemuPlan(command=command, forwards=forwards, accel=accel, kernel_path=kernel_path)


def write_qemu_command(layout: ArtifactLayout, plan: QemuPlan) -> None:
    layout.qemu_cmd.write_text(" ".join(shlex.quote(part) for part in plan.command) + "\n", encoding="utf-8")


def run_qemu(runner: CommandRunner, plan: QemuPlan, layout: ArtifactLayout) -> None:
    LOGGER.info("selected accelerator: %s (%s)", plan.accel.accel, plan.accel.reason)
    write_qemu_command(layout, plan)
    runner.run_interactive(plan.command, exit_code=ExitCode.QEMU_FAILURE)
