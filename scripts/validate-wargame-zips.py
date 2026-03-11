#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import socket
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WARGAME_DIR = ROOT / "wargame_zip"
REPORT_DIR = ROOT / "reports" / "wargame_zip"


@dataclass(slots=True)
class ValidationResult:
    target: str
    inspect_ok: bool
    dry_run_ok: bool
    run_ok: bool
    gdb_attach_ok: bool
    service_port: int | None
    gdb_multi_port: int | None
    gdb_attach_port: int | None
    notes: list[str]
    workdir: str

    def to_dict(self) -> dict[str, object]:
        return {
            "target": self.target,
            "inspect_ok": self.inspect_ok,
            "dry_run_ok": self.dry_run_ok,
            "run_ok": self.run_ok,
            "gdb_attach_ok": self.gdb_attach_ok,
            "service_port": self.service_port,
            "gdb_multi_port": self.gdb_multi_port,
            "gdb_attach_port": self.gdb_attach_port,
            "notes": self.notes,
            "workdir": self.workdir,
        }


def run_command(args: list[str], *, cwd: Path, timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True, timeout=timeout, check=False)


def wait_for_port(port: int, *, timeout: float = 25.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def try_interactive_payload(port: int) -> str | None:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
            sock.settimeout(2)
            sock.sendall(b"help\n")
            data = sock.recv(1024)
            return data.decode("latin1", "replace")
    except OSError:
        return None
    except TimeoutError:
        return ""


def try_gdb_connect(port: int, *, extended: bool) -> bool:
    target_cmd = f"target {'extended-remote' if extended else 'remote'} 127.0.0.1:{port}"
    result = subprocess.run(
        [
            "gdb",
            "-q",
            "-nx",
            "-ex",
            "set pagination off",
            "-ex",
            target_cmd,
            "-ex",
            "disconnect",
            "-ex",
            "quit",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=20,
        check=False,
    )
    return result.returncode == 0 and f"Remote debugging using 127.0.0.1:{port}" in result.stdout


def terminate_qemu() -> None:
    subprocess.run(["pkill", "-f", "qemu-system-x86_64"], check=False)


def validate_target(zip_path: Path) -> ValidationResult:
    name = zip_path.stem
    workdir = Path("/private/tmp") / f"contrace-validate-{name}"
    inspect_workdir = workdir.with_name(workdir.name + "-inspect")
    dry_run_workdir = workdir.with_name(workdir.name + "-dryrun")
    run_workdir = workdir.with_name(workdir.name + "-run")
    for path in (inspect_workdir, dry_run_workdir, run_workdir):
        if path.exists():
            shutil.rmtree(path)
    notes: list[str] = []

    inspect_cmd = [
        sys.executable,
        "-m",
        "contrace",
        "inspect",
        str(zip_path),
        "--json",
        "--keep-workdir",
        "--workdir",
        str(inspect_workdir),
    ]
    inspect_result = run_command(inspect_cmd, cwd=ROOT, timeout=240)
    inspect_ok = inspect_result.returncode == 0
    if not inspect_ok:
        notes.append(f"inspect failed: {inspect_result.stderr.strip() or inspect_result.stdout.strip()}")
        return ValidationResult(name, False, False, False, False, None, None, None, notes, str(workdir))

    inspect_runtime_path = inspect_workdir / "generated" / "runtime.json"
    if not inspect_runtime_path.exists():
        notes.append("inspect succeeded but runtime.json artifact is missing")
        return ValidationResult(name, False, False, False, False, None, None, None, notes, str(workdir))
    inspect_json = {"runtime": json.loads(inspect_runtime_path.read_text(encoding="utf-8"))}
    service_ports = inspect_json["runtime"]["service_ports"]
    service_port = service_ports[0] if service_ports else None
    gdb_multi_port = inspect_json["runtime"]["debug_multi_port"]
    gdb_attach_port = inspect_json["runtime"]["debug_attach_port"]

    dry_run_cmd = [
        sys.executable,
        "-m",
        "contrace",
        "run",
        str(zip_path),
        "--dry-run",
        "--keep-workdir",
        "--workdir",
        str(dry_run_workdir),
        "--disable-gdb-attach",
        "--no-shell",
    ]
    dry_run_result = run_command(dry_run_cmd, cwd=ROOT, timeout=240)
    dry_run_ok = dry_run_result.returncode == 0
    if not dry_run_ok:
        notes.append(f"dry-run failed: {dry_run_result.stderr.strip() or dry_run_result.stdout.strip()}")
        return ValidationResult(name, True, False, False, False, service_port, gdb_multi_port, gdb_attach_port, notes, str(workdir))

    terminate_qemu()
    run_cmd = [
        sys.executable,
        "-m",
        "contrace",
        "run",
        str(zip_path),
        "--keep-workdir",
        "--workdir",
        str(run_workdir),
        "--disable-gdb-attach",
        "--no-shell",
    ]
    run_stdout = REPORT_DIR / f"{name}.run.stdout.log"
    run_stderr = REPORT_DIR / f"{name}.run.stderr.log"
    proc = subprocess.Popen(
        run_cmd,
        cwd=ROOT,
        stdout=run_stdout.open("w", encoding="utf-8"),
        stderr=run_stderr.open("w", encoding="utf-8"),
        text=True,
        start_new_session=True,
    )

    try:
        if service_port is None:
            notes.append("no service port detected")
            run_ok = False
        else:
            service_ready = wait_for_port(service_port)
            payload = try_interactive_payload(service_port) if service_ready else None
            gdb_multi_ok = try_gdb_connect(gdb_multi_port, extended=True)
            run_ok = service_ready and gdb_multi_ok
            if not service_ready:
                notes.append(f"service port {service_port} did not open")
            if not gdb_multi_ok:
                notes.append(f"gdb multi connection to {gdb_multi_port} failed")
            if payload is not None:
                notes.append(f"service sample: {payload[:120]!r}")
            serial_log = run_workdir / "logs" / "serial.log"
            if serial_log.exists():
                serial_text = serial_log.read_text(encoding="utf-8", errors="replace")
                if "Kernel panic" in serial_text:
                    notes.append("serial log contained kernel panic")
                    run_ok = False
        gdb_attach_ok = False
    finally:
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=5)

    attach_cmd = [
        sys.executable,
        "-m",
        "contrace",
        "run",
        str(zip_path),
        "--keep-workdir",
        "--workdir",
        str(run_workdir.with_name(run_workdir.name + "-attach")),
        "--enable-gdb-attach",
        "--no-shell",
    ]
    attach_stdout = REPORT_DIR / f"{name}.attach.stdout.log"
    attach_stderr = REPORT_DIR / f"{name}.attach.stderr.log"
    attach_proc = subprocess.Popen(
        attach_cmd,
        cwd=ROOT,
        stdout=attach_stdout.open("w", encoding="utf-8"),
        stderr=attach_stderr.open("w", encoding="utf-8"),
        text=True,
        start_new_session=True,
    )
    try:
        gdb_attach_ok = try_gdb_connect(gdb_attach_port, extended=False)
        if not gdb_attach_ok:
            notes.append(f"gdb attach connection to {gdb_attach_port} failed")
    finally:
        os.killpg(attach_proc.pid, signal.SIGTERM)
        try:
            attach_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(attach_proc.pid, signal.SIGKILL)
            attach_proc.wait(timeout=5)

    return ValidationResult(
        name,
        True,
        True,
        run_ok,
        gdb_attach_ok,
        service_port,
        gdb_multi_port,
        gdb_attach_port,
        notes,
        str(run_workdir),
    )


def main() -> int:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    results: list[ValidationResult] = []
    for zip_path in sorted(WARGAME_DIR.glob("*.zip")):
        terminate_qemu()
        result = validate_target(zip_path)
        results.append(result)
        report_path = REPORT_DIR / f"{zip_path.stem}.json"
        report_path.write_text(json.dumps(result.to_dict(), indent=2) + "\n", encoding="utf-8")
        print(
            f"{zip_path.name}: inspect={result.inspect_ok} dry-run={result.dry_run_ok} "
            f"run={result.run_ok} gdb_attach={result.gdb_attach_ok}"
        )

    summary = {
        "results": [result.to_dict() for result in results],
        "all_passed": all(result.run_ok and result.gdb_attach_ok for result in results),
    }
    (REPORT_DIR / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
