from __future__ import annotations
from pathlib import Path


def find_line(source: str, line_number: int) -> str:
    lines = source.splitlines()
    if 1 <= line_number <= len(lines):
        return lines[line_number - 1]
    return ""


def read_file(file_path: str | Path) -> str:
    return Path(file_path).read_text(encoding="utf-8", errors="replace")
