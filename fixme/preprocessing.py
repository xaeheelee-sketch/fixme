from __future__ import annotations
import fnmatch
import re
import uuid
from pathlib import Path
import yaml
from .config import Config
from .feedback import FeedbackDB
from .models import VulnRecord, Severity


IGNORE_LINE = re.compile(
    r"//\s*metis-ignore\s*:\s*([\w\-,\s]+)"
    r"|/\*\s*metis-ignore\s*:\s*([\w\-,\s]+)\s*\*/"
)
IGNORE_NEXT = re.compile(
    r"//\s*metis-ignore-next-line\s*:\s*([\w\-,\s]+)"
    r"|/\*\s*metis-ignore-next-line\s*:\s*([\w\-,\s]+)\s*\*/"
)
IGNORE_BEGIN = re.compile(r"//\s*metis-ignore-begin\s*:\s*([\w\-,\s]+)")
IGNORE_END = re.compile(r"//\s*metis-ignore-end")


def parse_and_filter_vulnerabilities(
    raw_json: dict,
    config: Config,
    feedback_db: FeedbackDB,
    repo_root: Path,
) -> list[VulnRecord]:
    rules = _load_whitelist_rules(config.paths.whitelist_rules)
    rejected = feedback_db.rejected_signatures()
    out: list[VulnRecord] = []

    for review in raw_json.get("reviews", []):
        file_path = review.get("file_path", "")
        for finding in review.get("findings", []):
            vuln = _flatten(file_path, finding)
            if not _in_scope(vuln, config):
                continue
            if _matches_rule(vuln, rules):
                continue
            if _matches_inline_ignore(vuln, repo_root):
                continue
            sig = FeedbackDB.signature(vuln.cwe, vuln.code_snippet)
            if sig in rejected:
                continue
            out.append(vuln)

    return out


def group_by_file(vulns: list[VulnRecord]) -> dict[str, list[VulnRecord]]:
    grouped: dict[str, list[VulnRecord]] = {}
    for v in vulns:
        grouped.setdefault(v.file_path, []).append(v)
    for vs in grouped.values():
        vs.sort(key=lambda v: v.line_number)
    return grouped


def _flatten(file_path: str, finding: dict) -> VulnRecord:
    sev_str = finding.get("severity", "Low")
    return VulnRecord(
        vuln_id=finding.get("id") or uuid.uuid4().hex[:12],
        file_path=file_path,
        line_number=int(finding.get("line_number", 0)),
        cwe=finding.get("cwe", ""),
        severity=Severity.from_str(sev_str),
        code_snippet=finding.get("code_snippet", ""),
        description=finding.get("description", ""),
        raw=finding,
    )


def _in_scope(v: VulnRecord, cfg: Config) -> bool:
    if v.cwe not in cfg.scope.enabled_cwes:
        return False
    if v.severity < Severity.from_str(cfg.scope.min_severity):
        return False
    allow = cfg.scope.path_allowlist
    block = cfg.scope.path_blocklist
    if allow and not any(fnmatch.fnmatch(v.file_path, p) for p in allow):
        return False
    if block and any(fnmatch.fnmatch(v.file_path, p) for p in block):
        return False
    return True


def _matches_rule(v: VulnRecord, rules: list[dict]) -> bool:
    file_name = Path(v.file_path).name
    for r in rules:
        if r.get("file_name") and r["file_name"] != file_name:
            continue
        if r.get("cwe") and r["cwe"] != v.cwe:
            continue
        snippet = r.get("snippet_contains")
        if snippet and snippet not in v.code_snippet:
            continue
        return True
    return False


def _matches_inline_ignore(v: VulnRecord, repo_root: Path) -> bool:
    p = repo_root / v.file_path
    if not p.exists():
        return False
    try:
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return False
    target_idx = v.line_number - 1
    if not (0 <= target_idx < len(lines)):
        return False

    def matches_cwe(captured: str) -> bool:
        ids = [c.strip() for c in captured.split(",") if c.strip()]
        return v.cwe in ids

    target = lines[target_idx]
    m = IGNORE_LINE.search(target)
    if m and matches_cwe(m.group(1) or m.group(2) or ""):
        return True

    if target_idx > 0:
        m = IGNORE_NEXT.search(lines[target_idx - 1])
        if m and matches_cwe(m.group(1) or m.group(2) or ""):
            return True

    in_block: str | None = None
    for line in lines[: target_idx + 1]:
        b = IGNORE_BEGIN.search(line)
        if b:
            in_block = (b.group(1) or "").strip()
        elif IGNORE_END.search(line):
            in_block = None
    if in_block and matches_cwe(in_block):
        return True

    return False


def _load_whitelist_rules(path: str) -> list[dict]:
    p = Path(path)
    if not p.exists():
        return []
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or []
    return data if isinstance(data, list) else []
