from fixme.context import extract_function_or_window


def test_extracts_simple_function():
    src = (
        "int outer(void) { return 0; }\n"
        "\n"
        "static int compute(int x) {\n"
        "    int y = x;\n"
        "    return y;\n"
        "}\n"
        "\n"
        "void other(void) {}\n"
    )
    ctx = extract_function_or_window(src, line=4, window=3)
    assert "compute" in ctx
    assert "int y = x" in ctx
    assert "void other(void)" not in ctx


def test_falls_back_to_window_when_no_braces():
    src = "\n".join(f"line{i}" for i in range(1, 51))
    ctx = extract_function_or_window(src, line=25, window=3)
    lines = ctx.splitlines()
    assert "line25" in lines
    assert len(lines) <= 7


def test_handles_out_of_range():
    src = "int a;\n"
    assert extract_function_or_window(src, line=999) == ""
