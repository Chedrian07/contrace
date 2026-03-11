from __future__ import annotations

from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def static_tool_path(guest_arch: str, name: str) -> Path:
    return PROJECT_ROOT / "static" / guest_arch / name


def kernel_artifact_path(guest_arch: str) -> Path:
    return PROJECT_ROOT / "kernel" / guest_arch / "bzImage"


def kernel_artifact_hint_path(guest_arch: str) -> Path:
    return PROJECT_ROOT / "kernel" / guest_arch / "artifact-url.txt"
