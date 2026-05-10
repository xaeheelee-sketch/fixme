from __future__ import annotations
import argparse
import json
import sys
import time
from pathlib import Path

from fixme import fixers
from fixme.apply import PatchApplier
from fixme.budget import TokenBudget, BudgetExceeded
from fixme.config import load_config, Config
from fixme.context import extract_function_or_window
from fixme.explain import Explainer
from fixme.feedback import FeedbackDB
from fixme.llm_fixer import LlmFixer
from fixme.models import RunReportItem, VulnRecord
from fixme.output import OutputWriter
from fixme.preprocessing import parse_and_filter_vulnerabilities, group_by_file
from fixme.runners import (
    SubprocessRunner, CmdBuildRunner, CmdTestRunner, CmdSanitizerRunner,
    CmdMetisRunner, CliGitOps,
)
from fixme.tracer import JsonlTracer
from fixme.triage import Triager
from fixme.verification import Verifier


def main() -> int:
    parser = argparse.ArgumentParser(prog="fixme")
    parser.add_argument("--config", required=True, help="Path to config.yaml")
    parser.add_argument("--metis-input", required=True, help="Metis JSON file")
    parser.add_argument("--repo-root", required=True, help="Target repository root")
    args = parser.parse_args()

    config = load_config(args.config)
    repo_root = Path(args.repo_root).resolve()
    metis_json = json.loads(Path(args.metis_input).read_text(encoding="utf-8"))

    tracer = JsonlTracer(config.output_run_dir / "trace.jsonl")
    budget = TokenBudget(config.limits.per_run_token_budget)
    feedback = FeedbackDB(Path(config.paths.feedback_db))

    cmd_runner = SubprocessRunner()
    git_ops = CliGitOps(cmd_runner)
    build = CmdBuildRunner(config.runners.build_cmd, cmd_runner)
    test = CmdTestRunner(config.runners.test_cmd, cmd_runner)
    sanitizer = (
        CmdSanitizerRunner(config.runners.sanitizer_cmd, config.runners.test_cmd, cmd_runner)
        if config.runners.sanitizer_enabled and config.runners.sanitizer_cmd
        else None
    )
    metis_runner = CmdMetisRunner(config.runners.metis_cmd, cmd_runner)
    verifier = Verifier(build, test, sanitizer, metis_runner, repo_root)

    triager = Triager(config, budget, tracer)
    llm_fixer = LlmFixer(config, budget, tracer, verifier, git_ops, repo_root)
    explainer = Explainer(config, budget, tracer)
    applier = PatchApplier(config, git_ops, verifier, repo_root)
    writer = OutputWriter(config)

    branch = f"metis-autofix/{config.run_id}"
    try:
        git_ops.create_branch(repo_root, branch)
    except Exception as exc:
        tracer.log("branch_create_failed", error=str(exc))

    vulns = parse_and_filter_vulnerabilities(metis_json, config, feedback, repo_root)
    grouped = group_by_file(vulns)
    tracer.log("preprocessing_done", total=len(vulns), files=len(grouped))

    for _file_path, file_vulns in grouped.items():
        for vuln in file_vulns:
            try:
                _process_vuln(
                    vuln, repo_root, config, triager, llm_fixer, explainer, applier,
                    writer, tracer, feedback,
                )
            except BudgetExceeded as exc:
                tracer.log("budget_exceeded", error=str(exc))
                writer.add_report_item(RunReportItem(
                    vuln_id=vuln.vuln_id, cwe=vuln.cwe, severity=vuln.severity,
                    final_status="SKIPPED_BUDGET",
                ))
                writer.finalize()
                return 2
            except Exception as exc:
                tracer.log("vuln_error", vuln_id=vuln.vuln_id, error=str(exc))
                writer.add_report_item(RunReportItem(
                    vuln_id=vuln.vuln_id, cwe=vuln.cwe, severity=vuln.severity,
                    final_status="ERROR",
                ))

    writer.finalize()
    tracer.log("run_complete", run_id=config.run_id)
    return 0


def _process_vuln(
    vuln: VulnRecord,
    repo_root: Path,
    config: Config,
    triager: Triager,
    llm_fixer: LlmFixer,
    explainer: Explainer,
    applier: PatchApplier,
    writer: OutputWriter,
    tracer: JsonlTracer,
    feedback: FeedbackDB,
) -> None:
    t0 = time.time()
    src_path = repo_root / vuln.file_path
    if not src_path.exists():
        writer.add_report_item(RunReportItem(
            vuln_id=vuln.vuln_id, cwe=vuln.cwe, severity=vuln.severity,
            final_status="FILE_MISSING",
        ))
        return
    src = src_path.read_text(encoding="utf-8", errors="replace")
    ctx = extract_function_or_window(src, vuln.line_number, window=20)

    decision = triager.classify(vuln, ctx)
    route = triager.route(vuln, decision)
    item = RunReportItem(
        vuln_id=vuln.vuln_id, cwe=vuln.cwe, severity=vuln.severity,
        triage_label=decision.label,
    )

    if route == "SKIP":
        item.strategy = "SKIP"
        item.final_status = "SKIPPED"
        writer.add_report_item(item)
        return

    if route == "WHITELIST_CANDIDATE":
        writer.add_whitelist_candidate(vuln, decision.rationale)
        item.strategy = "SKIP"
        item.final_status = "WHITELIST_CANDIDATE"
        writer.add_report_item(item)
        return

    if route == "EXPLAIN_ONLY":
        exp = explainer.explain(vuln, ctx)
        writer.write_explanation(vuln, exp)
        item.strategy = "EXPLAIN_ONLY"
        item.final_status = "EXPLAINED"
        item.latency_ms = int((time.time() - t0) * 1000)
        writer.add_report_item(item)
        return

    if route == "DETERMINISTIC":
        succeeded = _try_deterministic(vuln, src, applier, writer, tracer)
        if succeeded:
            item.strategy = "DETERMINISTIC"
            item.final_status = "SUCCESS"
            item.attempts = 1
            item.latency_ms = int((time.time() - t0) * 1000)
            writer.add_report_item(item)
            return
        tracer.log("deterministic_escalate", vuln_id=vuln.vuln_id)

    _run_llm_fix(vuln, ctx, llm_fixer, writer, feedback, item, t0)


def _try_deterministic(
    vuln: VulnRecord, src: str, applier: PatchApplier,
    writer: OutputWriter, tracer: JsonlTracer,
) -> bool:
    fixer = fixers.get_fixer(vuln.cwe)
    if fixer is None:
        return False
    try:
        patch = fixer(vuln, src)
    except Exception as exc:
        tracer.log("deterministic_error", vuln_id=vuln.vuln_id, error=str(exc))
        return False
    if patch is None:
        return False
    status, error_log, diff = applier.apply_and_verify(vuln, patch, attempt=0, incremental=True)
    if status == "SUCCESS":
        writer.write_patch(vuln, diff)
        return True
    tracer.log(
        "deterministic_failed", vuln_id=vuln.vuln_id,
        status=status, error_log=error_log[:500],
    )
    return False


def _run_llm_fix(
    vuln: VulnRecord, ctx: str, llm_fixer: LlmFixer,
    writer: OutputWriter, feedback: FeedbackDB,
    item: RunReportItem, t0: float,
) -> None:
    negs = feedback.negative_examples_for(vuln.file_path, vuln.cwe)
    final_state = llm_fixer.run(vuln, ctx, negs)
    status = final_state.get("verify_status", "UNKNOWN")
    item.strategy = "LLM_FIX"
    item.attempts = final_state.get("retry_count", 0) + 1
    item.final_status = status
    item.latency_ms = int((time.time() - t0) * 1000)
    if status == "SUCCESS":
        diff = final_state.get("applied_diff", "")
        item.diff_path = writer.write_patch(vuln, diff)
    writer.add_report_item(item)


if __name__ == "__main__":
    sys.exit(main())
