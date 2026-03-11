from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Iterable


PORT_PATTERNS = [
    re.compile(r"TCP-LISTEN:(\d+)"),
    re.compile(r"(?:^|[ =])port(?:=| )(\d+)(?:\b|$)"),
    re.compile(r"http\.server(?:\s+|=)(\d+)"),
    re.compile(r"\b(?:nc|ncat)\b.*(?:-l|-lp|-lvp)\s+(\d+)"),
]


def classify_manager(argv: list[str]) -> str:
    if not argv:
        return "unknown"

    joined = " ".join(argv)
    head = PurePosixPath(argv[0]).name
    if head == "socat" or " socat " in f" {joined} ":
        return "socat"
    if head == "xinetd" or " xinetd" in joined:
        return "xinetd"
    if head == "inetd" or " inetd" in joined:
        return "inetd"
    if head == "supervisord" or " supervisord" in joined:
        return "supervisord"
    if head in {"sh", "bash"} and "-c" in argv:
        return "unknown"
    return "direct"


def infer_ports_from_argv(argv: list[str]) -> list[int]:
    if not argv:
        return []
    joined = " ".join(argv)
    ports: set[int] = set()
    for pattern in PORT_PATTERNS:
        for match in pattern.finditer(joined):
            ports.add(int(match.group(1)))
    return sorted(ports)


def parse_xinetd_configs(paths_to_text: Iterable[tuple[str, str]]) -> list[int]:
    ports: set[int] = set()
    for path, text in paths_to_text:
        if "/xinetd.d/" not in path:
            continue
        for line in text.splitlines():
            match = re.match(r"\s*port\s*=\s*(\d+)\s*$", line)
            if match:
                ports.add(int(match.group(1)))
    return sorted(ports)


def parse_inetd_conf(text: str) -> list[int]:
    ports: set[int] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if fields and fields[0].isdigit():
            ports.add(int(fields[0]))
    return sorted(ports)
