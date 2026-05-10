from fixme.fixers.cwe_457 import fix
from fixme.models import VulnRecord, Severity


def _vuln(line: int) -> VulnRecord:
    return VulnRecord(
        vuln_id="t1", file_path="src/x.c", line_number=line,
        cwe="CWE-457", severity=Severity.MEDIUM,
    )


def test_fixes_int_declaration():
    src = "int main(void) {\n    int counter;\n    return counter;\n}\n"
    patch = fix(_vuln(2), src)
    assert patch is not None
    assert patch.search_block == "    int counter;"
    assert patch.replace_block == "    int counter = 0;"
    assert patch.anchor_line == 2


def test_fixes_pointer_no_space():
    src = "void f(void) {\n    char *p;\n}\n"
    patch = fix(_vuln(2), src)
    assert patch is not None
    assert patch.replace_block == "    char *p = NULL;"


def test_fixes_pointer_trailing_space():
    src = "void f(void) {\n    char* p;\n}\n"
    patch = fix(_vuln(2), src)
    assert patch is not None
    assert "= NULL" in patch.replace_block


def test_fixes_struct_declaration():
    src = "void f(void) {\n    struct config cfg;\n}\n"
    patch = fix(_vuln(2), src)
    assert patch is not None
    assert patch.replace_block == "    struct config cfg = {0};"


def test_preserves_qualifiers():
    src = "void f(void) {\n    static int counter;\n}\n"
    patch = fix(_vuln(2), src)
    assert patch is not None
    assert patch.replace_block == "    static int counter = 0;"


def test_unsigned_two_word_type():
    src = "void f(void) {\n    unsigned int n;\n}\n"
    patch = fix(_vuln(2), src)
    assert patch is not None
    assert patch.replace_block == "    unsigned int n = 0;"


def test_returns_none_on_assignment():
    src = "void f(void) {\n    counter = 0;\n}\n"
    assert fix(_vuln(2), src) is None


def test_returns_none_on_function_signature():
    src = "int compute(int x) {\n    return x;\n}\n"
    assert fix(_vuln(1), src) is None


def test_returns_none_on_multi_decl():
    src = "void f(void) {\n    int a, b, c;\n}\n"
    assert fix(_vuln(2), src) is None


def test_returns_none_on_already_initialized():
    src = "void f(void) {\n    int counter = 5;\n}\n"
    assert fix(_vuln(2), src) is None
