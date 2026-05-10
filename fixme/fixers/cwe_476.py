from __future__ import annotations
import re
from typing import Optional
from ..models import VulnRecord, Patch
from .base import find_line


DEREF_ARROW = re.compile(r"(?<![A-Za-z0-9_])(?P<var>[A-Za-z_]\w*)\s*->\s*\w+")
DEREF_STAR = re.compile(r"(?<![A-Za-z0-9_*])\*(?P<var>[A-Za-z_]\w*)\b")
RESERVED = {"NULL", "this", "self", "void", "size_t", "true", "false"}


def fix(vuln: VulnRecord, source: str) -> Optional[Patch]:
    target_line = find_line(source, vuln.line_number)
    if not target_line.strip():
        return None
    if "assert(" in target_line:
        return None

    candidates = set(DEREF_ARROW.findall(target_line)) | set(DEREF_STAR.findall(target_line))
    candidates -= RESERVED
    if len(candidates) != 1:
        return None
    var = next(iter(candidates))

    if source.count(target_line) != 1:
        return None

    indent_match = re.match(r"^(\s*)", target_line)
    indent = indent_match.group(1) if indent_match else ""

    new_block = f"{indent}assert({var} != NULL);\n{target_line}"

    return Patch(
        file_path=vuln.file_path,
        search_block=target_line,
        replace_block=new_block,
        anchor_line=vuln.line_number,
        rationale=f"Insert null-check assertion for '{var}' before dereference.",
    )
