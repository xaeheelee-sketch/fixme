from fixme.fixers.cwe_190 import fix
from fixme.models import VulnRecord, Severity


def _vuln(line: int) -> VulnRecord:
    return VulnRecord(
        vuln_id="t1", file_path="src/x.c", line_number=line,
        cwe="CWE-190", severity=Severity.MEDIUM,
    )


def test_casts_var_to_size_t_in_malloc():
    src = "void f(int n) {\n    char *p = malloc(n * sizeof(int));\n}\n"
    patch = fix(_vuln(2), src)
    assert patch is not None
    assert "(size_t)n * sizeof(int)" in patch.replace_block
    assert patch.replace_block == "    char *p = malloc((size_t)n * sizeof(int));"


def test_casts_with_long_identifier():
    src = "void f(int count) {\n    char *p = malloc(count * sizeof(struct entry));\n}\n"
    patch = fix(_vuln(2), src)
    assert patch is not None
    assert "(size_t)count * sizeof(struct entry)" in patch.replace_block


def test_skips_when_already_cast():
    src = "void f(int n) {\n    char *p = malloc((size_t)n * sizeof(int));\n}\n"
    assert fix(_vuln(2), src) is None


def test_skips_when_no_sizeof():
    src = "void f(int n) {\n    int x = n * 4;\n}\n"
    assert fix(_vuln(2), src) is None


def test_skips_when_left_operand_is_literal():
    src = "void f(void) {\n    char *p = malloc(2 * sizeof(int));\n}\n"
    assert fix(_vuln(2), src) is None


def test_skips_when_multiple_sizeof_muls():
    src = (
        "void f(int n, int m) {\n"
        "    char *p = malloc(n * sizeof(int) + m * sizeof(int));\n"
        "}\n"
    )
    assert fix(_vuln(2), src) is None
