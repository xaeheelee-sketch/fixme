from __future__ import annotations


def extract_function_or_window(text: str, line: int, window: int = 20) -> str:
    """Best-effort: extract enclosing function via brace balance, fallback to ±window lines."""
    lines = text.splitlines()
    n = len(lines)
    if not (1 <= line <= n):
        return ""
    idx = line - 1

    start = max(0, idx - window)
    depth = 0
    for i in range(idx, -1, -1):
        depth += lines[i].count("}") - lines[i].count("{")
        if depth < 0:
            start = i
            break

    end = min(n - 1, idx + window)
    depth = 0
    seen_open = False
    for i in range(start, n):
        opens = lines[i].count("{")
        closes = lines[i].count("}")
        depth += opens - closes
        if opens:
            seen_open = True
        if seen_open and depth == 0:
            end = i
            break

    if end - start > 200:
        start = max(0, idx - window)
        end = min(n - 1, idx + window)
    return "\n".join(lines[start:end + 1])
