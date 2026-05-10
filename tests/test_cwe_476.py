from fixme.fixers.cwe_476 import fix
from fixme.models import VulnRecord, Severity


def _vuln(line: int) -> VulnRecord:
    return VulnRecord(
        vuln_id="t1", file_path="src/x.c", line_number=line,
        cwe="CWE-476", severity=Severity.HIGH,
    )


def test_inserts_assert_for_arrow_deref():
    src = "void f(struct s *p) {\n    p->field = 1;\n}\n"
    patch = fix(_vuln(2), src)
    assert patch is not None
    assert "assert(p != NULL);" in patch.replace_block
    assert patch.replace_block.endswith("    p->field = 1;")
    assert patch.search_block == "    p->field = 1;"


def test_inserts_assert_for_star_deref():
    src = "void f(int *q) {\n    *q = 1;\n}\n"
    patch = fix(_vuln(2), src)
    assert patch is not None
    assert "assert(q != NULL);" in patch.replace_block


def test_skips_ambiguous_multiple_pointers():
    src = "void f(int *a, int *b) {\n    a->x = b->y;\n}\n"
    assert fix(_vuln(2), src) is None


def test_skips_already_asserted_line():
    src = (
        "void f(int *p) {\n"
        "    assert(p != NULL); p->x = 1;\n"
        "}\n"
    )
    assert fix(_vuln(2), src) is None


def test_skips_no_pointer_deref():
    src = "void f(int x) {\n    x = 1;\n}\n"
    assert fix(_vuln(2), src) is None


def test_preserves_indentation():
    src = (
        "void f(struct s *p) {\n"
        "    if (cond) {\n"
        "        p->field = 1;\n"
        "    }\n"
        "}\n"
    )
    patch = fix(_vuln(3), src)
    assert patch is not None
    lines = patch.replace_block.splitlines()
    assert lines[0] == "        assert(p != NULL);"
    assert lines[1] == "        p->field = 1;"
