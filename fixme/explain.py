from __future__ import annotations
from langchain_openai import ChatOpenAI
from .config import Config
from .models import ExplanationOutput, VulnRecord
from .budget import TokenBudget
from .tracer import JsonlTracer


EXPLAIN_SYSTEM = """You explain C/C++ security findings that are NOT suitable for automated patching.
Produce a concise explanation focusing on root cause and a suggested approach.
Do not generate code."""


class Explainer:
    def __init__(self, config: Config, budget: TokenBudget, tracer: JsonlTracer):
        self.config = config
        self.budget = budget
        self.tracer = tracer
        self.llm = ChatOpenAI(
            model=config.models.analyzer,
            base_url=config.api_base,
            api_key=config.api_key,
            temperature=0.2,
        ).with_structured_output(ExplanationOutput)

    def explain(self, vuln: VulnRecord, code_context: str) -> ExplanationOutput:
        prompt = (
            f"File: {vuln.file_path}:{vuln.line_number}\n"
            f"CWE: {vuln.cwe}\n"
            f"Severity: {vuln.severity.name}\n"
            f"Description: {vuln.description}\n\n"
            f"Code context:\n```c\n{code_context}\n```"
        )
        try:
            return self.llm.invoke(
                [{"role": "system", "content": EXPLAIN_SYSTEM},
                 {"role": "user", "content": prompt}]
            )
        except Exception as exc:
            self.tracer.log("explain_error", vuln_id=vuln.vuln_id, error=str(exc))
            return ExplanationOutput(
                summary="(explainer failed)",
                root_cause=str(exc),
                suggested_approach="Manual review required.",
                risk_if_unfixed="Unknown.",
                estimated_complexity="HIGH",
            )
