from __future__ import annotations
from langchain_openai import ChatOpenAI
from .config import Config
from .models import TriageDecision, VulnRecord
from .budget import TokenBudget
from .tracer import JsonlTracer
from . import fixers


TRIAGE_SYSTEM = """You are a security triage assistant for C/C++ static analysis findings.
Classify the given vulnerability into one of:
- TP_SIMPLE: true positive, mechanical fix likely safe
- TP_DESIGN: true positive but requires design-level change
- FALSE_POSITIVE: not a real vulnerability in this context
- OUT_OF_SCOPE: out of remediation scope (third-party, generated)

Choose suggested_strategy:
- DETERMINISTIC: rule-based fix is sufficient
- LLM_FIX: requires LLM-generated patch
- EXPLAIN_ONLY: produce explanation, do not patch
- SKIP: no action

Be conservative. Lower confidence when unsure."""


class Triager:
    def __init__(self, config: Config, budget: TokenBudget, tracer: JsonlTracer):
        self.config = config
        self.budget = budget
        self.tracer = tracer
        self.llm = ChatOpenAI(
            model=config.models.triage,
            base_url=config.api_base,
            api_key=config.api_key,
            temperature=0.0,
        ).with_structured_output(TriageDecision)

    def classify(self, vuln: VulnRecord, code_context: str) -> TriageDecision:
        prompt = self._build_prompt(vuln, code_context)
        try:
            decision: TriageDecision = self.llm.invoke(
                [{"role": "system", "content": TRIAGE_SYSTEM},
                 {"role": "user", "content": prompt}]
            )
        except Exception as exc:
            self.tracer.log("triage_error", vuln_id=vuln.vuln_id, error=str(exc))
            return TriageDecision(
                label="OUT_OF_SCOPE", confidence=0.0,
                rationale=f"Triage failed: {exc}", suggested_strategy="SKIP",
            )
        self.tracer.log(
            "triage", vuln_id=vuln.vuln_id, label=decision.label,
            strategy=decision.suggested_strategy, confidence=decision.confidence,
        )
        return decision

    def route(self, vuln: VulnRecord, decision: TriageDecision) -> str:
        if decision.label == "FALSE_POSITIVE":
            return "WHITELIST_CANDIDATE"
        if decision.label == "OUT_OF_SCOPE" or decision.confidence < 0.6:
            return "SKIP"
        if self._is_safety_critical(vuln) or decision.label == "TP_DESIGN":
            return "EXPLAIN_ONLY"
        if decision.label == "TP_SIMPLE":
            if fixers.supports(vuln.cwe) and decision.suggested_strategy == "DETERMINISTIC":
                return "DETERMINISTIC"
            return "LLM_FIX"
        return "SKIP"

    def _is_safety_critical(self, vuln: VulnRecord) -> bool:
        import fnmatch
        for pat in self.config.scope.safety_critical_paths:
            if fnmatch.fnmatch(vuln.file_path, pat):
                return True
        return False

    @staticmethod
    def _build_prompt(vuln: VulnRecord, code_context: str) -> str:
        return (
            f"File: {vuln.file_path}\n"
            f"Line: {vuln.line_number}\n"
            f"CWE: {vuln.cwe}\n"
            f"Severity: {vuln.severity.name}\n"
            f"Description: {vuln.description}\n\n"
            f"Code context:\n```c\n{code_context}\n```"
        )
