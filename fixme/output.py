from __future__ import annotations
import json
from .config import Config
from .models import RunReportItem, ExplanationOutput, VulnRecord


class OutputWriter:
    def __init__(self, config: Config):
        self.config = config
        self.run_dir = config.output_run_dir
        self.run_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir / "patches").mkdir(exist_ok=True)
        (self.run_dir / "explanations").mkdir(exist_ok=True)
        self._items: list[RunReportItem] = []
        self._whitelist_candidates: list[dict] = []

    def write_patch(self, vuln: VulnRecord, diff: str) -> str:
        path = self.run_dir / "patches" / f"{vuln.vuln_id}.patch"
        path.write_text(diff, encoding="utf-8")
        return str(path)

    def write_explanation(self, vuln: VulnRecord, exp: ExplanationOutput) -> str:
        path = self.run_dir / "explanations" / f"{vuln.vuln_id}.md"
        body = (
            f"# {vuln.cwe} @ {vuln.file_path}:{vuln.line_number}\n\n"
            f"**Severity**: {vuln.severity.name}\n"
            f"**Complexity**: {exp.estimated_complexity}\n\n"
            f"## Summary\n{exp.summary}\n\n"
            f"## Root cause\n{exp.root_cause}\n\n"
            f"## Suggested approach\n{exp.suggested_approach}\n\n"
            f"## Risk if unfixed\n{exp.risk_if_unfixed}\n"
        )
        path.write_text(body, encoding="utf-8")
        return str(path)

    def add_whitelist_candidate(self, vuln: VulnRecord, rationale: str) -> None:
        self._whitelist_candidates.append({
            "vuln_id": vuln.vuln_id,
            "file_path": vuln.file_path,
            "line_number": vuln.line_number,
            "cwe": vuln.cwe,
            "rationale": rationale,
        })

    def add_report_item(self, item: RunReportItem) -> None:
        self._items.append(item)

    def finalize(self) -> None:
        report = {
            "run_id": self.config.run_id,
            "items": [i.model_dump() for i in self._items],
        }
        (self.run_dir / "report.json").write_text(
            json.dumps(report, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        (self.run_dir / "whitelist_candidates.json").write_text(
            json.dumps(self._whitelist_candidates, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        self._write_summary()

    def _write_summary(self) -> None:
        n = len(self._items)
        succ = sum(1 for i in self._items if i.final_status == "SUCCESS")
        det = sum(1 for i in self._items if i.strategy == "DETERMINISTIC")
        llm = sum(1 for i in self._items if i.strategy == "LLM_FIX")
        exp = sum(1 for i in self._items if i.strategy == "EXPLAIN_ONLY")
        wl = len(self._whitelist_candidates)
        body = (
            f"# Run {self.config.run_id} Summary\n\n"
            f"- Total processed: {n}\n"
            f"- Successful patches: {succ}\n"
            f"- Deterministic / LLM / Explain: {det} / {llm} / {exp}\n"
            f"- Whitelist candidates: {wl}\n"
        )
        (self.run_dir / "summary.md").write_text(body, encoding="utf-8")
