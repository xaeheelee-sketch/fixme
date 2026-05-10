from __future__ import annotations
import re
from typing import Optional
from ..models import VulnRecord, Patch
from .base import find_line

DECL_PATTERN = re.compile(
    r"^(?P<indent>\s*)"
    r"(?P<quals>(?:(?:static|extern|register|volatile|const)\s+)*)"
    r"(?P<type>(?:struct\s+\w+|unsigned\s+\w+|signed\s+\w+|\w+))"
    r"(?P<sep>\s+\*?\s*|\s*\*\s*)"
    r"(?P<name>\w+)\s*;\s*$"
)


def fix(vuln: VulnRecord, source: str) -> Optional[Patch]:
    target_line = find_line(source, vuln.line_number)
    m = DECL_PATTERN.match(target_line)
    if not m:
        return None
    indent = m.group("indent")
    quals = m.group("quals")
    type_token = m.group("type")
    sep = m.group("sep")
    name = m.group("name")

    is_pointer = "*" in sep
    if is_pointer:
        init = " = NULL"
    elif type_token.startswith("struct"):
        init = " = {0}"
    else:
        init = " = 0"
    new_line = f"{indent}{quals}{type_token}{sep}{name}{init};"

    return Patch(
        file_path=vuln.file_path,
        search_block=target_line,
        replace_block=new_line,
        anchor_line=vuln.line_number,
        rationale=f"Initialize '{name}' at declaration to avoid CWE-457.",
    )
