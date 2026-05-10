from __future__ import annotations
import re

SUSPICIOUS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("system_call", re.compile(r"\bsystem\s*\(")),
    ("exec_family", re.compile(r"\bexec[lv]p?e?\s*\(")),
    ("popen", re.compile(r"\bpopen\s*\(")),
    ("external_url", re.compile(r"https?://(?!localhost|127\.0\.0\.1)")),
    ("ip_literal", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("base64_blob", re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")),
    ("dead_branch", re.compile(r"\bif\s*\(\s*0\s*\)")),
]


def scan_replace_block(replace_block: str, original_block: str) -> list[str]:
    findings: list[str] = []
    for name, pat in SUSPICIOUS_PATTERNS:
        new_count = len(pat.findall(replace_block))
        old_count = len(pat.findall(original_block))
        if new_count > old_count:
            findings.append(name)
    return findings
