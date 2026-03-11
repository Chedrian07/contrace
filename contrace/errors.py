from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class ExitCode(IntEnum):
    SUCCESS = 0
    INVALID_INPUT = 2
    DOCKER_FAILURE = 3
    RUNTIME_FAILURE = 4
    GUEST_ASSEMBLY_FAILURE = 5
    QEMU_FAILURE = 6
    BOOT_FAILURE = 7


@dataclass(slots=True)
class ContraceError(Exception):
    message: str
    exit_code: ExitCode

    def __str__(self) -> str:
        return self.message
