from pathlib import Path
import pytest
from fixme.config import (
    Config, ScopeConfig, ModelsConfig, LimitsConfig, RunnersConfig, PathsConfig,
)
from fixme.feedback import FeedbackDB
from fixme.preprocessing import parse_and_filter_vulnerabilities, group_by_file


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config(
        run_id="test",
        api_base="http://localhost",
        api_key_env="UNUSED",
        scope=ScopeConfig(
            enabled_cwes=["CWE-457", "CWE-476"],
            min_severity="Medium",
            path_allowlist=["src/**"],
            path_blocklist=["src/vendor/**"],
            safety_critical_paths=[],
        ),
        models=ModelsConfig(triage="m", fixer="m", analyzer="m"),
        limits=LimitsConfig(),
        runners=RunnersConfig(build_cmd="", test_cmd="", metis_cmd=""),
        paths=PathsConfig(
            whitelist_rules=str(tmp_path / "wl.yaml"),
            feedback_db=str(tmp_path / "fb.jsonl"),
            output_dir=str(tmp_path / "out"),
        ),
    )


@pytest.fixture
def empty_db(tmp_path: Path) -> FeedbackDB:
    return FeedbackDB(tmp_path / "fb.jsonl")


def _make_raw(file_path: str, findings: list[dict]) -> dict:
    return {"reviews": [{"file_path": file_path, "findings": findings}]}


def test_severity_filter(config, empty_db, tmp_path):
    raw = _make_raw("src/a.c", [
        {"id": "1", "line_number": 10, "cwe": "CWE-457", "severity": "Low",
         "code_snippet": "int x;"},
        {"id": "2", "line_number": 20, "cwe": "CWE-457", "severity": "High",
         "code_snippet": "int y;"},
    ])
    out = parse_and_filter_vulnerabilities(raw, config, empty_db, tmp_path)
    ids = [v.vuln_id for v in out]
    assert ids == ["2"]


def test_cwe_scope_filter(config, empty_db, tmp_path):
    raw = _make_raw("src/a.c", [
        {"id": "1", "line_number": 10, "cwe": "CWE-999", "severity": "High",
         "code_snippet": "x"},
    ])
    out = parse_and_filter_vulnerabilities(raw, config, empty_db, tmp_path)
    assert out == []


def test_path_blocklist(config, empty_db, tmp_path):
    raw = _make_raw("src/vendor/lib.c", [
        {"id": "1", "line_number": 10, "cwe": "CWE-457", "severity": "High",
         "code_snippet": "x"},
    ])
    out = parse_and_filter_vulnerabilities(raw, config, empty_db, tmp_path)
    assert out == []


def test_path_allowlist_excludes_outside(config, empty_db, tmp_path):
    raw = _make_raw("docs/notes.c", [
        {"id": "1", "line_number": 10, "cwe": "CWE-457", "severity": "High",
         "code_snippet": "x"},
    ])
    out = parse_and_filter_vulnerabilities(raw, config, empty_db, tmp_path)
    assert out == []


def test_inline_ignore_same_line(config, empty_db, tmp_path):
    src = tmp_path / "src" / "a.c"
    src.parent.mkdir(parents=True)
    src.write_text("int x;\nint y; // metis-ignore: CWE-457\nint z;\n")
    raw = _make_raw("src/a.c", [
        {"id": "1", "line_number": 2, "cwe": "CWE-457", "severity": "High",
         "code_snippet": "int y;"},
    ])
    out = parse_and_filter_vulnerabilities(raw, config, empty_db, tmp_path)
    assert out == []


def test_inline_ignore_next_line(config, empty_db, tmp_path):
    src = tmp_path / "src" / "a.c"
    src.parent.mkdir(parents=True)
    src.write_text("// metis-ignore-next-line: CWE-457\nint y;\n")
    raw = _make_raw("src/a.c", [
        {"id": "1", "line_number": 2, "cwe": "CWE-457", "severity": "High",
         "code_snippet": "int y;"},
    ])
    out = parse_and_filter_vulnerabilities(raw, config, empty_db, tmp_path)
    assert out == []


def test_inline_ignore_block(config, empty_db, tmp_path):
    src = tmp_path / "src" / "a.c"
    src.parent.mkdir(parents=True)
    src.write_text(
        "// metis-ignore-begin: CWE-457\n"
        "int x;\n"
        "int y;\n"
        "// metis-ignore-end\n"
        "int z;\n"
    )
    raw = _make_raw("src/a.c", [
        {"id": "1", "line_number": 2, "cwe": "CWE-457", "severity": "High",
         "code_snippet": "int x;"},
        {"id": "2", "line_number": 5, "cwe": "CWE-457", "severity": "High",
         "code_snippet": "int z;"},
    ])
    out = parse_and_filter_vulnerabilities(raw, config, empty_db, tmp_path)
    ids = [v.vuln_id for v in out]
    assert ids == ["2"]


def test_inline_ignore_multiple_cwes(config, empty_db, tmp_path):
    src = tmp_path / "src" / "a.c"
    src.parent.mkdir(parents=True)
    src.write_text("int *p; // metis-ignore: CWE-120, CWE-457\n")
    raw = _make_raw("src/a.c", [
        {"id": "1", "line_number": 1, "cwe": "CWE-457", "severity": "High",
         "code_snippet": "int *p;"},
    ])
    out = parse_and_filter_vulnerabilities(raw, config, empty_db, tmp_path)
    assert out == []


def test_group_by_file_sorts_by_line():
    from fixme.models import VulnRecord, Severity
    vs = [
        VulnRecord(vuln_id="b", file_path="src/a.c", line_number=20,
                   cwe="CWE-457", severity=Severity.HIGH),
        VulnRecord(vuln_id="a", file_path="src/a.c", line_number=5,
                   cwe="CWE-457", severity=Severity.HIGH),
        VulnRecord(vuln_id="c", file_path="src/b.c", line_number=1,
                   cwe="CWE-457", severity=Severity.HIGH),
    ]
    grouped = group_by_file(vs)
    assert list(grouped.keys()) == ["src/a.c", "src/b.c"]
    assert [v.vuln_id for v in grouped["src/a.c"]] == ["a", "b"]
