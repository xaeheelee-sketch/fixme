from __future__ import annotations
import hashlib
import json
from pathlib import Path
from .models import FeedbackRecord


class FeedbackDB:
    def __init__(self, path: Path):
        self.path = path
        self.records: list[FeedbackRecord] = []
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    self.records.append(FeedbackRecord(**json.loads(line)))

    def rejected_signatures(self) -> set[str]:
        return {r.vuln_signature for r in self.records if r.decision == "REJECTED"}

    def negative_examples_for(self, file_path: str, cwe: str) -> list[dict]:
        return [
            r.model_dump()
            for r in self.records
            if r.decision == "REJECTED" and r.cwe == cwe and r.file == file_path
        ]

    @staticmethod
    def signature(cwe: str, normalized_context: str) -> str:
        normalized = " ".join(normalized_context.split())
        h = hashlib.sha256(f"{cwe}|{normalized}".encode()).hexdigest()
        return h[:16]
