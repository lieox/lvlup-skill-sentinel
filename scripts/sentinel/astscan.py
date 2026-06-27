"""AST-based detection for Python; token-based for JS/TS.

Catches dynamic-exec and indirection that flat regex misses (eval/exec/__import__,
getattr-based call indirection, subprocess shell=True). NEVER executes the code: Python
goes through ast.parse only; JS/TS is a bounded token scan.
"""
from __future__ import annotations

import ast
import re

CRITICAL, HIGH, MED, LOW = "CRITICAL", "HIGH", "MED", "LOW"

_DANGER_CALLS = {"eval", "exec", "compile", "__import__"}


def _finding(category, severity, rule, filename, line, snippet):
    return {"category": category, "severity": severity, "rule": rule,
            "file": filename, "line": line, "snippet": snippet[:160]}


def scan_python(text: str, filename: str) -> list[dict]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []  # unparseable: regex layer still covers it
    src_lines = text.splitlines()
    out: list[dict] = []

    def snip(node):
        ln = getattr(node, "lineno", 0)
        return (src_lines[ln - 1].strip() if 0 < ln <= len(src_lines) else "")

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            # eval/exec/compile/__import__ - ONLY a bare-name call is dangerous.
            # Attribute calls like re.compile(...) or obj.eval(...) are not.
            if isinstance(fn, ast.Name) and fn.id in _DANGER_CALLS:
                out.append(_finding("obfuscation", HIGH,
                                    f"dynamic exec ({fn.id})", filename,
                                    getattr(node, "lineno", 0), snip(node)))
            # getattr call indirection: the RESULT of getattr is immediately invoked,
            # e.g. getattr(os, 'system')('id'). A plain getattr(obj, name) retrieval is fine.
            if (isinstance(fn, ast.Call) and isinstance(fn.func, ast.Name)
                    and fn.func.id == "getattr"):
                out.append(_finding("obfuscation", HIGH,
                                    "getattr call indirection", filename,
                                    getattr(node, "lineno", 0), snip(node)))
            # subprocess.* / os.system with shell=True building a command from a variable.
            # A constant string command (subprocess.run("ls -la", shell=True)) is not flagged;
            # only a dynamically-built command is (the injection risk).
            if isinstance(fn, ast.Attribute) and fn.attr in ("run", "call", "Popen", "check_output", "system"):
                shell_true = any(
                    isinstance(k, ast.keyword) and k.arg == "shell"
                    and isinstance(k.value, ast.Constant) and k.value.value is True
                    for k in node.keywords
                )
                cmd_arg = node.args[0] if node.args else None
                cmd_is_constant = isinstance(cmd_arg, ast.Constant) and isinstance(cmd_arg.value, str)
                if shell_true and not cmd_is_constant:
                    out.append(_finding("destructive", HIGH,
                                        f"shell=True subprocess ({fn.attr})", filename,
                                        getattr(node, "lineno", 0), snip(node)))
    return out


_JS_RULES = [
    ("obfuscation", HIGH, re.compile(r"(?<![\w.])eval\s*\("), "dynamic exec (eval)"),
    ("obfuscation", HIGH, re.compile(r"new\s+Function\s*\("), "JS Function constructor"),
    ("obfuscation", HIGH, re.compile(r"child_process"), "node child_process"),
    ("obfuscation", HIGH, re.compile(r"\bvm\.runIn"), "node vm runIn* exec"),
]


def scan_js(text: str, filename: str) -> list[dict]:
    out = []
    lines = text.splitlines()
    for category, severity, pat, rule in _JS_RULES:
        for m in pat.finditer(text):
            ln = text.count("\n", 0, m.start()) + 1
            snippet = lines[ln - 1].strip() if 0 < ln <= len(lines) else m.group(0)
            out.append(_finding(category, severity, rule, filename, ln, snippet))
    return out


def scan_code(text: str, filename: str) -> list[dict]:
    low = filename.lower()
    if low.endswith(".py"):
        return scan_python(text, filename)
    if low.endswith((".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")):
        return scan_js(text, filename)
    return []
