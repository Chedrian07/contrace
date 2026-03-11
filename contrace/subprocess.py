from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from contrace.errors import ContraceError, ExitCode

LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str


class CommandRunner:
    def _format_failure(self, args: Sequence[str], returncode: int, stderr: str) -> str:
        detail = stderr.strip()
        if detail:
            return f"command failed ({returncode}): {' '.join(args)}\n{detail}"
        return f"command failed ({returncode}): {' '.join(args)}"

    def run(
        self,
        args: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        check: bool = True,
        exit_code: ExitCode = ExitCode.DOCKER_FAILURE,
    ) -> CommandResult:
        LOGGER.debug("running command: %s", " ".join(args))
        completed = subprocess.run(
            list(args),
            cwd=str(cwd) if cwd else None,
            env=dict(env) if env else None,
            capture_output=True,
            text=True,
            check=False,
        )
        result = CommandResult(
            args=list(args),
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
        if check and completed.returncode != 0:
            raise ContraceError(
                self._format_failure(args, completed.returncode, completed.stderr),
                exit_code,
            )
        return result

    def run_to_file(
        self,
        args: Sequence[str],
        output_path: Path,
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        check: bool = True,
        exit_code: ExitCode = ExitCode.DOCKER_FAILURE,
    ) -> CommandResult:
        LOGGER.debug("running command to file: %s > %s", " ".join(args), output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("wb") as handle:
            completed = subprocess.run(
                list(args),
                cwd=str(cwd) if cwd else None,
                env=dict(env) if env else None,
                stdout=handle,
                stderr=subprocess.PIPE,
                check=False,
            )
        stderr = completed.stderr.decode("utf-8", errors="replace")
        result = CommandResult(
            args=list(args),
            returncode=completed.returncode,
            stdout="",
            stderr=stderr,
        )
        if check and completed.returncode != 0:
            raise ContraceError(
                self._format_failure(args, completed.returncode, stderr),
                exit_code,
            )
        return result

    def run_interactive(
        self,
        args: Sequence[str],
        *,
        cwd: Path | None = None,
        env: Mapping[str, str] | None = None,
        exit_code: ExitCode = ExitCode.QEMU_FAILURE,
    ) -> int:
        LOGGER.debug("running interactive command: %s", " ".join(args))
        completed = subprocess.run(
            list(args),
            cwd=str(cwd) if cwd else None,
            env=dict(env) if env else None,
            check=False,
        )
        if completed.returncode != 0:
            raise ContraceError(
                self._format_failure(args, completed.returncode, ""),
                exit_code,
            )
        return completed.returncode
