from fixme.fixers.cwe_401 import fix
from fixme.models import VulnRecord, Severity


def _vuln(line: int) -> VulnRecord:
    return VulnRecord(
        vuln_id="t1", file_path="src/x.c", line_number=line,
        cwe="CWE-401", severity=Severity.MEDIUM,
    )


def test_inserts_free_before_return_in_braced_block():
    src = (
        "int f(void) {\n"
        "    char *buf = malloc(100);\n"
        "    if (something_failed()) {\n"
        "        return -1;\n"
        "    }\n"
        "    free(buf);\n"
        "    return 0;\n"
        "}\n"
    )
    patch = fix(_vuln(4), src)
    assert patch is not None
    assert "free(buf);" in patch.replace_block
    assert "        free(buf);" in patch.replace_block
    assert "return -1;" in patch.replace_block


def test_skips_when_already_freed_before_return():
    src = (
        "int f(void) {\n"
        "    char *buf = malloc(100);\n"
        "    free(buf);\n"
        "    return -1;\n"
        "}\n"
    )
    assert fix(_vuln(4), src) is None


def test_skips_when_no_alloc_in_function():
    src = "int f(void) {\n    return -1;\n}\n"
    assert fix(_vuln(2), src) is None


def test_skips_braceless_conditional_return():
    src = (
        "int f(void) {\n"
        "    char *buf = malloc(100);\n"
        "    if (cond)\n"
        "        return -1;\n"
        "    free(buf);\n"
        "    return 0;\n"
        "}\n"
    )
    assert fix(_vuln(4), src) is None


def test_handles_calloc():
    src = (
        "int f(void) {\n"
        "    int *p = calloc(10, sizeof(int));\n"
        "    if (err()) {\n"
        "        return -1;\n"
        "    }\n"
        "    free(p);\n"
        "    return 0;\n"
        "}\n"
    )
    patch = fix(_vuln(4), src)
    assert patch is not None
    assert "free(p);" in patch.replace_block


def test_skips_non_return_line():
    src = (
        "int f(void) {\n"
        "    char *buf = malloc(100);\n"
        "    do_thing(buf);\n"
        "}\n"
    )
    assert fix(_vuln(3), src) is None
