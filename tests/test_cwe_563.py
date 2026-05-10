from fixme.fixers.cwe_563 import fix
from fixme.models import VulnRecord, Severity


def _vuln(line: int) -> VulnRecord:
    return VulnRecord(
        vuln_id="t1", file_path="src/x.c", line_number=line,
        cwe="CWE-563", severity=Severity.LOW,
    )


def test_removes_unused_simple_decl():
    src = "void f(void) {\n    int unused;\n    return;\n}\n"
    patch = fix(_vuln(2), src)
    assert patch is not None
    assert patch.search_block == "    int unused;\n"
    assert patch.replace_block == ""


def test_removes_unused_initialized_decl():
    src = "void f(void) {\n    int unused = 0;\n}\n"
    patch = fix(_vuln(2), src)
    assert patch is not None
    assert patch.replace_block == ""


def test_removes_unused_pointer():
    src = "void f(void) {\n    char *unused = NULL;\n}\n"
    patch = fix(_vuln(2), src)
    assert patch is not None


def test_keeps_used_var():
    src = "void f(void) {\n    int x;\n    x = 5;\n}\n"
    assert fix(_vuln(2), src) is None


def test_keeps_var_used_in_expression():
    src = "int f(void) {\n    int total;\n    return total + 1;\n}\n"
    assert fix(_vuln(2), src) is None


def test_skips_non_decl_line():
    src = "void f(void) {\n    do_thing();\n}\n"
    assert fix(_vuln(2), src) is None


def test_skips_decl_with_function_call_init():
    src = "void f(void) {\n    int x = compute();\n}\n"
    assert fix(_vuln(2), src) is None
