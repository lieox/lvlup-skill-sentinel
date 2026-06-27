from sentinel.astscan import scan_python, scan_js, scan_code


def _rules(findings):
    return {f["rule"] for f in findings}


def test_python_flags_eval():
    f = scan_python("x = eval(user_input)", "a.py")
    assert any(x["category"] == "obfuscation" for x in f)
    assert any("eval" in x["rule"] for x in f)


def test_python_flags_exec():
    f = scan_python("exec(open('p').read())", "a.py")
    assert any("exec" in x["rule"] for x in f)


def test_python_flags_dunder_import():
    f = scan_python("m = __import__('os')", "a.py")
    assert any("__import__" in x["rule"] for x in f)


def test_python_flags_getattr_indirection():
    f = scan_python("getattr(os, 'system')('id')", "a.py")
    assert any("getattr" in x["rule"] for x in f)


def test_python_flags_subprocess_shell_true():
    f = scan_python("import subprocess\nsubprocess.run(cmd, shell=True)", "a.py")
    assert any(x["category"] == "destructive" for x in f)


def test_python_clean_code_no_findings():
    assert scan_python("def add(a, b):\n    return a + b\n", "a.py") == []


def test_python_syntax_error_falls_back_quietly():
    # unparseable Python must not raise; returns [] (regex layer still covers it)
    assert scan_python("def (:::", "a.py") == []


def test_js_flags_eval_and_function_ctor():
    f = scan_js("eval(x); const g = new Function('a','return a');", "a.js")
    rules = _rules(f)
    assert any("eval" in r for r in rules)
    assert any("Function" in r for r in rules)


def test_js_flags_child_process():
    f = scan_js("const cp = require('child_process')", "a.js")
    assert any("child_process" in x["rule"] for x in f)


def test_scan_code_routes_by_suffix():
    assert scan_code("eval(x)", "a.py")  # python path
    assert scan_code("eval(x)", "a.js")  # js path
    assert scan_code("eval(x)", "a.txt") == []  # unsupported suffix


def test_re_compile_not_flagged():
    # re.compile is an attribute call, not a bare exec/compile builtin - must not flag
    assert scan_python("import re\np = re.compile(r'x')", "a.py") == []


def test_plain_getattr_not_flagged():
    # a plain getattr retrieval (result not invoked) is benign
    assert scan_python("v = getattr(obj, name)", "a.py") == []


def test_static_shell_true_not_flagged():
    # a constant string command with shell=True carries no injection risk - must not flag
    assert scan_python("import subprocess\nsubprocess.run('ls -la', shell=True)", "a.py") == []


def test_dynamic_shell_true_flagged_high():
    f = scan_python("import subprocess\nsubprocess.run(cmd, shell=True)", "a.py")
    assert any(x["category"] == "destructive" and x["severity"] == "HIGH" for x in f)
