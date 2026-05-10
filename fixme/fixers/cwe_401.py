from __future__ import annotations
import re
from typing import Optional
from ..models import VulnRecord, Patch


RETURN = re.compile(r"^\s*return\b")
ALLOC = re.compile(
    r"^.*?(?P<var>[A-Za-z_]\w*)\s*=\s*"
    r"(?:malloc|calloc|realloc|strdup|strndup)\s*\("
)


def fix(vuln: VulnRecord, source: str) -> Optional[Patch]:
    lines = source.splitlines(keepends=True)
    idx = vuln.line_number - 1
    if not (0 <= idx < len(lines)):
        return None

    target_line = lines[idx]
    if not RETURN.match(target_line):
        return None

    if _previous_is_braceless_control(lines, idx):
        return None

    func_start = _find_function_start(lines, idx)
    if func_start is None:
        return None

    candidate_var: Optional[str] = None
    candidate_line = -1
    for i in range(func_start, idx):
        m = ALLOC.match(lines[i])
        if m:
            candidate_var = m.group("var")
            candidate_line = i
    if candidate_var is None:
        return None

    free_pat = re.compile(rf"\bfree\s*\(\s*{re.escape(candidate_var)}\s*\)")
    for i in range(candidate_line + 1, idx):
        if free_pat.search(lines[i]):
            return None

    indent_match = re.match(r"^(\s*)", target_line)
    indent = indent_match.group(1) if indent_match else ""

    ctx_start = max(func_start, idx - 3)
    search = "".join(lines[ctx_start:idx + 1]).rstrip("\n")
    if source.count(search) != 1:
        return None

    new_lines = list(lines[ctx_start:idx])
    new_lines.append(f"{indent}free({candidate_var});\n")
    new_lines.append(target_line)
    replace = "".join(new_lines).rstrip("\n")

    return Patch(
        file_path=vuln.file_path,
        search_block=search,
        replace_block=replace,
        anchor_line=vuln.line_number,
        rationale=f"Free '{candidate_var}' before return to avoid leak.",
    )


def _previous_is_braceless_control(lines: list[str], idx: int) -> bool:
    j = idx - 1
    while j >= 0 and not lines[j].strip():
        j -= 1
    if j < 0:
        return False
    prev = lines[j].rstrip()
    return prev.endswith(")")


def _find_function_start(lines: list[str], idx: int) -> Optional[int]:
    depth = 0
    outermost_open: Optional[int] = None
    for i in range(idx, -1, -1):
        depth += lines[i].count("}") - lines[i].count("{")
        if depth < 0:
            outermost_open = i
            depth = 0
    return outermost_open
