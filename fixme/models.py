from __future__ import annotations
from enum import IntEnum
from typing import Literal, Optional, TypedDict
from pydantic import BaseModel, Field


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, s: str) -> "Severity":
        return cls[s.upper()]


VerifyStatus = Literal[
    "SUCCESS",
    "FAILED_BUILD",
    "FAILED_TEST",
    "FAILED_SANITIZER",
    "FAILED_METIS_RECHECK",
    "FAILED_SAFETY_SCAN",
    "FAILED_DIFF_TOO_LARGE",
    "FAILED_PATCH_APPLY",
]

TriageLabel = Literal["TP_SIMPLE", "TP_DESIGN", "FALSE_POSITIVE", "OUT_OF_SCOPE"]
Strategy = Literal["DETERMINISTIC", "LLM_FIX", "EXPLAIN_ONLY", "SKIP"]


class VulnRecord(BaseModel):
    vuln_id: str
    file_path: str
    line_number: int
    cwe: str
    severity: Severity
    code_snippet: str = ""
    description: str = ""
    raw: dict = Field(default_factory=dict)


class TriageDecision(BaseModel):
    label: TriageLabel
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    suggested_strategy: Strategy


class Patch(BaseModel):
    file_path: str
    search_block: str
    replace_block: str
    anchor_line: int
    rationale: str = ""


class FixOutput(BaseModel):
    search_block: str
    replace_block: str
    anchor_line: int
    rationale: str
    changes_behavior: bool


class ExplanationOutput(BaseModel):
    summary: str
    root_cause: str
    suggested_approach: str
    risk_if_unfixed: str
    estimated_complexity: Literal["LOW", "MEDIUM", "HIGH"]


class VerifyResult(BaseModel):
    status: VerifyStatus
    error_log: str = ""
    metis_findings_after: int = 0
    duration_ms: int = 0


class FeedbackRecord(BaseModel):
    vuln_signature: str
    file: str
    line_range: tuple[int, int]
    cwe: str
    decision: Literal["MERGED", "REJECTED", "MODIFIED"]
    reason: Optional[str] = None
    reviewer: Optional[str] = None
    ts: str


class RunReportItem(BaseModel):
    vuln_id: str
    cwe: str
    severity: Severity
    triage_label: Optional[TriageLabel] = None
    strategy: Optional[Strategy] = None
    attempts: int = 0
    final_status: str = "PENDING"
    diff_path: Optional[str] = None
    tokens_in: int = 0
    tokens_out: int = 0
    latency_ms: int = 0
    cost_estimate: float = 0.0


class AgentState(TypedDict, total=False):
    vuln_info: dict
    original_code_context: str
    current_fixed_code: dict
    applied_diff: str
    file_sha_before: str
    retry_count: int
    attempt_history: list[dict]
    negative_examples: list[dict]
    error_log: str
    error_analysis_hint: str
    verify_status: VerifyStatus
    commit_made: bool
