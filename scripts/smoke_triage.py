"""Smoke test: single triage call against the internal LLM gateway.

Usage:
  set INTERNAL_LLM_API_KEY=...
  python scripts/smoke_triage.py --config config.yaml
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fixme.budget import TokenBudget
from fixme.config import load_config
from fixme.models import Severity, VulnRecord
from fixme.tracer import JsonlTracer
from fixme.triage import Triager


SAMPLE_VULN = VulnRecord(
    vuln_id="smoke-1",
    file_path="src/example.c",
    line_number=4,
    cwe="CWE-457",
    severity=Severity.MEDIUM,
    code_snippet="int counter;",
    description="Use of uninitialized variable 'counter' before assignment.",
)

SAMPLE_CONTEXT = """static int compute(int x) {
    int counter;
    if (x > 0) {
        counter += 1;
    }
    return counter;
}"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()

    config = load_config(args.config)
    if not config.api_key:
        print(f"ERROR: env var {config.api_key_env} is empty", file=sys.stderr)
        return 1

    tracer = JsonlTracer(Path("smoke-trace.jsonl"))
    budget = TokenBudget(100_000)
    triager = Triager(config, budget, tracer)

    print(f"Model:    {config.models.triage}")
    print(f"Endpoint: {config.api_base}\n")
    print("Sample vulnerability:")
    print(f"  {SAMPLE_VULN.cwe} @ {SAMPLE_VULN.file_path}:{SAMPLE_VULN.line_number}")
    print(f"  {SAMPLE_VULN.description}\n")

    decision = triager.classify(SAMPLE_VULN, SAMPLE_CONTEXT)
    route = triager.route(SAMPLE_VULN, decision)

    print("Triage result:")
    print(f"  Label:      {decision.label}")
    print(f"  Confidence: {decision.confidence:.2f}")
    print(f"  Strategy:   {decision.suggested_strategy}")
    print(f"  Rationale:  {decision.rationale}")
    print(f"  Route:      {route}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
