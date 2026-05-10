from __future__ import annotations
import time
from pathlib import Path
from .models import VerifyResult, VulnRecord
from .runners import BuildRunner, TestRunner, SanitizerRunner, MetisRunner


class Verifier:
    def __init__(
        self,
        build: BuildRunner,
        test: TestRunner,
        sanitizer: SanitizerRunner | None,
        metis: MetisRunner,
        repo_root: Path,
    ):
        self.build = build
        self.test = test
        self.sanitizer = sanitizer
        self.metis = metis
        self.repo_root = repo_root

    def verify(self, vuln: VulnRecord, incremental: bool = False) -> VerifyResult:
        t0 = time.time()

        b = self.build.build(self.repo_root)
        if b.returncode != 0:
            return self._fail("FAILED_BUILD", b.stderr, t0)

        t = self.test.test(self.repo_root)
        if t.returncode != 0:
            return self._fail("FAILED_TEST", t.stderr, t0)

        if self.sanitizer is not None:
            s = self.sanitizer.build_and_test(self.repo_root)
            if s.returncode != 0:
                return self._fail("FAILED_SANITIZER", s.stderr, t0)

        scan_files = [vuln.file_path] if incremental else None
        try:
            report = self.metis.scan(self.repo_root, files=scan_files)
        except Exception as exc:
            return self._fail("FAILED_METIS_RECHECK", f"metis scan failed: {exc}", t0)

        new_findings = self._count_findings(report, exclude_id=vuln.vuln_id)
        original_present = self._has_finding(report, vuln_id=vuln.vuln_id)
        if original_present or new_findings > 0:
            return VerifyResult(
                status="FAILED_METIS_RECHECK",
                error_log=f"original_present={original_present}, new_findings={new_findings}",
                metis_findings_after=new_findings,
                duration_ms=int((time.time() - t0) * 1000),
            )

        return VerifyResult(status="SUCCESS", duration_ms=int((time.time() - t0) * 1000))

    @staticmethod
    def _fail(status: str, log: str, t0: float) -> VerifyResult:
        return VerifyResult(
            status=status,  # type: ignore[arg-type]
            error_log=log[-4000:],
            duration_ms=int((time.time() - t0) * 1000),
        )

    @staticmethod
    def _count_findings(report: dict, exclude_id: str) -> int:
        n = 0
        for r in report.get("reviews", []):
            for f in r.get("findings", []):
                if f.get("id") != exclude_id:
                    n += 1
        return n

    @staticmethod
    def _has_finding(report: dict, vuln_id: str) -> bool:
        for r in report.get("reviews", []):
            for f in r.get("findings", []):
                if f.get("id") == vuln_id:
                    return True
        return False
