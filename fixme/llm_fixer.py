from __future__ import annotations
import hashlib
from pathlib import Path
from langchain_openai import ChatOpenAI
from langgraph.graph import StateGraph, END
from .config import Config
from .models import AgentState, FixOutput, VulnRecord, VerifyResult
from .budget import TokenBudget
from .tracer import JsonlTracer
from .safety import scan_replace_block
from .verification import Verifier
from .runners import GitOps
from .context import extract_function_or_window


FIX_SYSTEM_BASE = """You generate minimal, correct C/C++ patches that fix Metis-detected security findings.
Output ONLY the structured fields requested.
search_block must be a verbatim substring of the original file with exactly one occurrence.
Preserve original whitespace and indentation in search_block.
Keep replace_block as small as possible — change only what is needed to remove the vulnerability."""

FIX_SYSTEM_RETRY1 = (
    FIX_SYSTEM_BASE
    + "\nThe previous attempt failed verification. Apply the analyzer hint."
)
FIX_SYSTEM_RETRY2 = (
    FIX_SYSTEM_BASE
    + "\nThis is the FINAL attempt. Produce the smallest possible patch. "
    "Do not change observable behavior. Do not introduce new function calls."
)

ANALYZER_SYSTEM = """You analyze build/test/sanitizer/Metis errors after a failed C/C++ patch attempt.
Produce a short hint (1-3 sentences) for the next fix attempt.
Focus on root cause and what NOT to repeat."""


class LlmFixer:
    def __init__(
        self,
        config: Config,
        budget: TokenBudget,
        tracer: JsonlTracer,
        verifier: Verifier,
        git_ops: GitOps,
        repo_root: Path,
    ):
        self.config = config
        self.budget = budget
        self.tracer = tracer
        self.verifier = verifier
        self.git_ops = git_ops
        self.repo_root = repo_root

        self._fixer_llms = {
            i: ChatOpenAI(
                model=config.models.fixer,
                base_url=config.api_base,
                api_key=config.api_key,
                temperature=0.1 + 0.1 * i,
            ).with_structured_output(FixOutput)
            for i in range(config.limits.max_retries + 1)
        }
        self._analyzer = ChatOpenAI(
            model=config.models.analyzer,
            base_url=config.api_base,
            api_key=config.api_key,
            temperature=0.4,
        )
        self.graph = self._build_graph()

    def run(
        self,
        vuln: VulnRecord,
        code_context: str,
        negative_examples: list[dict],
    ) -> dict:
        initial: AgentState = {
            "vuln_info": vuln.model_dump(),
            "original_code_context": code_context,
            "current_fixed_code": {},
            "applied_diff": "",
            "file_sha_before": "",
            "retry_count": 0,
            "attempt_history": [],
            "negative_examples": negative_examples,
            "error_log": "",
            "error_analysis_hint": "",
            "verify_status": "FAILED_PATCH_APPLY",
            "commit_made": False,
        }
        return self.graph.invoke(initial)

    def _build_graph(self):
        g = StateGraph(AgentState)
        g.add_node("retrieve_context", self._retrieve_context_node)
        g.add_node("generate_fix", self._generate_fix_node)
        g.add_node("apply_patch", self._apply_patch_node)
        g.add_node("verify", self._verify_node)
        g.add_node("analyze_error", self._analyze_error_node)
        g.add_node("rollback", self._rollback_node)

        g.set_entry_point("retrieve_context")
        g.add_edge("retrieve_context", "generate_fix")
        g.add_edge("generate_fix", "apply_patch")
        g.add_conditional_edges(
            "apply_patch",
            self._after_apply,
            {"verify": "verify", "retry": "analyze_error", "end": END},
        )
        g.add_conditional_edges(
            "verify",
            self._after_verify,
            {"ok": END, "rollback": "rollback"},
        )
        g.add_conditional_edges(
            "rollback",
            self._after_rollback,
            {"retry": "analyze_error", "end": END},
        )
        g.add_edge("analyze_error", "generate_fix")
        return g.compile()

    def _retrieve_context_node(self, state: AgentState) -> dict:
        vuln = VulnRecord(**state["vuln_info"])
        path = self.repo_root / vuln.file_path
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return {
                "error_log": f"cannot read source: {exc}",
                "verify_status": "FAILED_PATCH_APPLY",
            }
        ctx = extract_function_or_window(text, vuln.line_number, window=20)
        sha = hashlib.sha256(text.encode()).hexdigest()
        return {"original_code_context": ctx, "file_sha_before": sha}

    def _generate_fix_node(self, state: AgentState) -> dict:
        retry = state.get("retry_count", 0)
        system = [FIX_SYSTEM_BASE, FIX_SYSTEM_RETRY1, FIX_SYSTEM_RETRY2][min(retry, 2)]
        user = self._build_fix_prompt(state)
        idx = min(retry, max(self._fixer_llms.keys()))
        llm = self._fixer_llms[idx]
        try:
            fix: FixOutput = llm.invoke(
                [{"role": "system", "content": system},
                 {"role": "user", "content": user}]
            )
        except Exception as exc:
            self.tracer.log("fix_error", error=str(exc), retry=retry)
            return {
                "error_log": f"LLM fix failed: {exc}",
                "verify_status": "FAILED_PATCH_APPLY",
                "commit_made": False,
            }
        return {"current_fixed_code": fix.model_dump(), "commit_made": False}

    def _apply_patch_node(self, state: AgentState) -> dict:
        vuln = VulnRecord(**state["vuln_info"])
        fix = state.get("current_fixed_code") or {}
        if not fix:
            return {
                "error_log": "no fix produced",
                "verify_status": "FAILED_PATCH_APPLY",
                "commit_made": False,
            }

        path = self.repo_root / vuln.file_path
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return {
                "error_log": f"read failed: {exc}",
                "verify_status": "FAILED_PATCH_APPLY",
                "commit_made": False,
            }

        current_sha = hashlib.sha256(text.encode()).hexdigest()
        if current_sha != state.get("file_sha_before"):
            return {
                "error_log": "file changed externally between read and write",
                "verify_status": "FAILED_PATCH_APPLY",
                "commit_made": False,
            }

        search = fix["search_block"]
        replace = fix["replace_block"]
        anchor = int(fix.get("anchor_line", vuln.line_number))

        count = text.count(search)
        if count != 1:
            return {
                "error_log": f"search_block matched {count}x (expected 1)",
                "verify_status": "FAILED_PATCH_APPLY",
                "commit_made": False,
            }

        match_pos = text.index(search)
        match_line = text[:match_pos].count("\n") + 1
        if abs(match_line - anchor) > 3:
            return {
                "error_log": f"line drift {match_line} vs anchor {anchor}",
                "verify_status": "FAILED_PATCH_APPLY",
                "commit_made": False,
            }

        diff_lines = max(search.count("\n"), replace.count("\n")) + 1
        if diff_lines > self.config.limits.max_diff_lines:
            return {
                "error_log": f"diff lines {diff_lines} exceeds limit",
                "verify_status": "FAILED_DIFF_TOO_LARGE",
                "commit_made": False,
            }

        bad = scan_replace_block(replace, search)
        if bad:
            return {
                "error_log": f"safety scan flagged: {bad}",
                "verify_status": "FAILED_SAFETY_SCAN",
                "commit_made": False,
            }

        new_text = text.replace(search, replace, 1)
        try:
            path.write_text(new_text, encoding="utf-8")
        except OSError as exc:
            return {
                "error_log": f"write failed: {exc}",
                "verify_status": "FAILED_PATCH_APPLY",
                "commit_made": False,
            }

        msg = (
            f"fix(metis): {vuln.cwe} @ {vuln.file_path}:{vuln.line_number} "
            f"[attempt {state.get('retry_count', 0)}]"
        )
        try:
            self.git_ops.commit(self.repo_root, msg, [vuln.file_path])
            diff = self.git_ops.diff(self.repo_root, [vuln.file_path])
        except Exception as exc:
            return {
                "error_log": f"git commit failed: {exc}",
                "verify_status": "FAILED_PATCH_APPLY",
                "commit_made": False,
            }

        return {
            "applied_diff": diff,
            "verify_status": "SUCCESS",
            "commit_made": True,
        }

    def _verify_node(self, state: AgentState) -> dict:
        vuln = VulnRecord(**state["vuln_info"])
        result: VerifyResult = self.verifier.verify(vuln, incremental=False)
        return {"verify_status": result.status, "error_log": result.error_log}

    def _analyze_error_node(self, state: AgentState) -> dict:
        retry = state.get("retry_count", 0)
        history = list(state.get("attempt_history", []))
        history.append({
            "retry": retry,
            "fix": state.get("current_fixed_code", {}),
            "error_log": state.get("error_log", ""),
            "verify_status": state.get("verify_status", ""),
        })
        prompt = self._build_analyzer_prompt(state, history)
        try:
            resp = self._analyzer.invoke(
                [{"role": "system", "content": ANALYZER_SYSTEM},
                 {"role": "user", "content": prompt}]
            )
            hint = getattr(resp, "content", str(resp))
        except Exception as exc:
            hint = f"(analyzer failed: {exc})"
        return {
            "error_analysis_hint": hint,
            "attempt_history": history,
            "retry_count": retry + 1,
        }

    def _rollback_node(self, state: AgentState) -> dict:
        if state.get("commit_made"):
            try:
                self.git_ops.reset_hard_head_minus_one(self.repo_root)
            except Exception as exc:
                self.tracer.log("rollback_error", error=str(exc))
        return {"commit_made": False}

    def _after_apply(self, state: AgentState) -> str:
        if state.get("commit_made"):
            return "verify"
        if state.get("retry_count", 0) < self.config.limits.max_retries - 1:
            return "retry"
        return "end"

    def _after_verify(self, state: AgentState) -> str:
        return "ok" if state.get("verify_status") == "SUCCESS" else "rollback"

    def _after_rollback(self, state: AgentState) -> str:
        if state.get("verify_status") == "SUCCESS":
            return "end"
        if state.get("retry_count", 0) < self.config.limits.max_retries - 1:
            return "retry"
        return "end"

    @staticmethod
    def _build_fix_prompt(state: AgentState) -> str:
        vuln = state["vuln_info"]
        ctx = state["original_code_context"]
        hint = state.get("error_analysis_hint", "")
        history = state.get("attempt_history", [])
        negs = state.get("negative_examples", [])
        parts = [
            f"CWE: {vuln.get('cwe')}",
            f"File: {vuln.get('file_path')}:{vuln.get('line_number')}",
            f"Description: {vuln.get('description')}",
            "",
            "Code context:",
            f"```c\n{ctx}\n```",
        ]
        if hint:
            parts += ["", f"Analyzer hint from previous failure: {hint}"]
        if history:
            parts += ["", "Previous attempts (do not repeat):"]
            for h in history[-3:]:
                parts.append(
                    f"- attempt {h['retry']}: {h['verify_status']} — "
                    f"{(h.get('error_log') or '')[:200]}"
                )
        if negs:
            parts += ["", "Past rejected patterns for this file/CWE — avoid:"]
            for n in negs[:3]:
                parts.append(f"- reason: {n.get('reason', 'n/a')}")
        return "\n".join(parts)

    @staticmethod
    def _build_analyzer_prompt(state: AgentState, history: list[dict]) -> str:
        last = history[-1]
        return (
            f"Verify status: {last['verify_status']}\n"
            f"Last fix:\n{last['fix']}\n\n"
            f"Error log:\n{(last['error_log'] or '')[:3000]}\n\n"
            f"Code context:\n```c\n{state['original_code_context']}\n```"
        )
