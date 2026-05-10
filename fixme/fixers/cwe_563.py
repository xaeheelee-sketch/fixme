from __future__ import annotations
import re
from typing import Optional
from ..models import VulnRecord, Patch
from .base import find_line


SIMPLE_DECL = re.compile(
    r"^(?P<indent>\s*)"
    r"(?:(?:static|extern|register|volatile|const)\s+)*"
    r"(?:struct\s+\w+|unsigned\s+\w+|signed\s+\w+|\w+)"
    r"(?:\s+\*?\s*|\s*\*\s*)"
    r"(?P<name>\w+)"
    r"(?:\s*=\s*(?:0|NULL|false|true|\"\"|''|0x0|\{\s*0?\s*\}))?"
    r"\s*;\s*$"
)


def fix(vuln: VulnRecord, source: str) -> Optional[Patch]:
    target_line = find_line(source, vuln.line_number)
    m = SIMPLE_DECL.match(target_line)
    if not m:
        return None
    name = m.group("name")

    word_pat = re.compile(rf"\b{re.escape(name)}\b")
    if len(word_pat.findall(source)) > 1:
        return None

    search = target_line + "\n"
    if source.count(search) != 1:
        return None

    return Patch(
        file_path=vuln.file_path,
        search_block=search,
        replace_block="",
        anchor_line=vuln.line_number,
        rationale=f"Remove unused variable '{name}'.",
    )
