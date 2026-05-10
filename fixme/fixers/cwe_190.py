from __future__ import annotations
import re
from typing import Optional
from ..models import VulnRecord, Patch
from .base import find_line


SIZEOF_MUL = re.compile(
    r"(?<![A-Za-z0-9_])(?P<var>[A-Za-z_]\w*)\s*\*\s*sizeof\s*\("
)


def fix(vuln: VulnRecord, source: str) -> Optional[Patch]:
    target_line = find_line(source, vuln.line_number)
    if not target_line:
        return None

    matches = list(SIZEOF_MUL.finditer(target_line))
    if len(matches) != 1:
        return None
    m = matches[0]
    var = m.group("var")

    if f"(size_t){var}" in target_line or f"(size_t) {var}" in target_line:
        return None

    if source.count(target_line) != 1:
        return None

    new_line = (
        target_line[:m.start()]
        + f"(size_t){var} * sizeof("
        + target_line[m.end():]
    )

    return Patch(
        file_path=vuln.file_path,
        search_block=target_line,
        replace_block=new_line,
        anchor_line=vuln.line_number,
        rationale=f"Cast '{var}' to size_t before sizeof multiplication to prevent overflow.",
    )
