from __future__ import annotations
from pathlib import Path
from .config import Config
from .models import Patch, VerifyResult, VulnRecord
from .runners import GitOps
from .safety import scan_replace_block
from .verification import Verifier


class PatchApplier:
    """Shared apply+verify path used by deterministic fixers and (out-of-band) tests."""

    def __init__(self, config: Config, git_ops: GitOps, verifier: Verifier, repo_root: Path):
        self.config = config
        self.git_ops = git_ops
        self.verifier = verifier
        self.repo_root = repo_root

    def apply_and_verify(
        self,
        vuln: VulnRecord,
        patch: Patch,
        attempt: int = 0,
        incremental: bool = False,
    ) -> tuple[str, str, str]:
        path = self.repo_root / vuln.file_path
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return "FAILED_PATCH_APPLY", f"read failed: {exc}", ""

        count = text.count(patch.search_block)
        if count != 1:
            return "FAILED_PATCH_APPLY", f"search_block matched {count}x (expected 1)", ""

        match_pos = text.index(patch.search_block)
        match_line = text[:match_pos].count("\n") + 1
        if abs(match_line - patch.anchor_line) > 3:
            return (
                "FAILED_PATCH_APPLY",
                f"line drift {match_line} vs anchor {patch.anchor_line}",
                "",
            )

        diff_lines = max(patch.search_block.count("\n"), patch.replace_block.count("\n")) + 1
        if diff_lines > self.config.limits.max_diff_lines:
            return "FAILED_DIFF_TOO_LARGE", f"diff lines {diff_lines}", ""

        bad = scan_replace_block(patch.replace_block, patch.search_block)
        if bad:
            return "FAILED_SAFETY_SCAN", f"flagged: {bad}", ""

        new_text = text.replace(patch.search_block, patch.replace_block, 1)
        try:
            path.write_text(new_text, encoding="utf-8")
        except OSError as exc:
            return "FAILED_PATCH_APPLY", f"write failed: {exc}", ""

        msg = (
            f"fix(metis): {vuln.cwe} @ {vuln.file_path}:{vuln.line_number} "
            f"[attempt {attempt}]"
        )
        try:
            self.git_ops.commit(self.repo_root, msg, [vuln.file_path])
            diff = self.git_ops.diff(self.repo_root, [vuln.file_path])
        except Exception as exc:
            return "FAILED_PATCH_APPLY", f"git commit failed: {exc}", ""

        result: VerifyResult = self.verifier.verify(vuln, incremental=incremental)
        if result.status != "SUCCESS":
            try:
                self.git_ops.reset_hard_head_minus_one(self.repo_root)
            except Exception:
                pass
        return result.status, result.error_log, diff
