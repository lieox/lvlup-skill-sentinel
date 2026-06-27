"""Dependency + typosquat analysis. Parses declared deps (npm/pip/pyproject/MCP launch cmd),
flags names that are 1-edit away from a known package, and flags unpinned versions. Stdlib only.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

MED, LOW = "MED", "LOW"
_REF = Path(__file__).resolve().parents[2] / "references" / "known-packages.txt"


def _f(rule, severity, filename, snippet, line=1):
    return {"category": "supply_chain", "severity": severity, "rule": rule,
            "file": filename, "line": line, "snippet": str(snippet)[:160]}


@lru_cache(maxsize=1)
def known_packages() -> frozenset:
    try:
        lines = _REF.read_text("utf-8").splitlines()
    except OSError:
        return frozenset()
    return frozenset(ln.strip().lower() for ln in lines
                     if ln.strip() and not ln.strip().startswith("#"))


def _lev(a: str, b: str) -> int:
    """Optimal string alignment distance (handles transpositions as cost 1)."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return 2  # only care about <=1; short-circuit for speed
    dp = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        dp[i][0] = i
    for j in range(lb + 1):
        dp[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(
                dp[i - 1][j] + 1,
                dp[i][j - 1] + 1,
                dp[i - 1][j - 1] + cost,
            )
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                dp[i][j] = min(dp[i][j], dp[i - 2][j - 2] + cost)
    return dp[la][lb]


def typosquat_check(name: str, known) -> str | None:
    n = (name or "").strip().lower()
    if not n or n in known:
        return None
    for k in known:
        if _lev(n, k) == 1:
            return k
    return None


def _strip_npm_version(spec: str) -> bool:
    """Return True if the npm version is UNPINNED (range/latest/*)."""
    s = (spec or "").strip()
    return s in ("", "*", "latest") or s[0] in "^~><" or "x" in s.lower().split(".")[-1:]


def _scan_package_json(p: Path, rel, known):
    out = []
    try:
        data = json.loads(p.read_text("utf-8", "replace"))
    except (OSError, json.JSONDecodeError):
        return out
    deps = {}
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        d = data.get(key)
        if isinstance(d, dict):
            deps.update(d)
    for name, spec in deps.items():
        hit = typosquat_check(name, known)
        if hit:
            out.append(_f(f"possible typosquat of '{hit}' (dep '{name}')", MED, rel, name))
        elif _strip_npm_version(str(spec)):
            out.append(_f(f"unpinned dependency '{name}'", LOW, rel, f"{name}: {spec}"))
    return out


def _scan_requirements(p: Path, rel, known):
    out = []
    try:
        lines = p.read_text("utf-8", "replace").splitlines()
    except OSError:
        return out
    for ln in lines:
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)\s*(.*)$", ln)
        if not m:
            continue
        name, rest = m.group(1), m.group(2)
        hit = typosquat_check(name, known)
        if hit:
            out.append(_f(f"possible typosquat of '{hit}' (dep '{name}')", MED, rel, ln))
        elif "==" not in rest:
            out.append(_f(f"unpinned dependency '{name}'", LOW, rel, ln))
    return out


_MCP_PKG = re.compile(r"\b(?:npx|uvx)\b[^\"']*?\s(?:-y\s+)?([A-Za-z0-9@._/-]+)")


def _scan_mcp_cmd(p: Path, rel, known):
    out = []
    try:
        data = json.loads(p.read_text("utf-8", "replace"))
    except (OSError, json.JSONDecodeError):
        return out
    servers = data.get("mcpServers") or data.get("servers") or {}
    vals = servers.values() if isinstance(servers, dict) else servers
    for cfg in vals:
        if not isinstance(cfg, dict):
            continue
        cmd = " ".join([str(cfg.get("command", ""))] + [str(a) for a in cfg.get("args", []) or []])
        for m in _MCP_PKG.finditer(cmd):
            pkg = m.group(1).split("@")[0].split("/")[-1]
            hit = typosquat_check(pkg, known)
            if hit:
                out.append(_f(f"possible typosquat of '{hit}' (MCP pkg '{pkg}')", MED, rel, cmd))
    return out


def scan_supply_chain(root: Path) -> list[dict]:
    root = Path(root)
    known = known_packages()
    out = []
    for p in root.rglob("*"):
        if not p.is_file() or ".git/" in str(p):
            continue
        rel = str(p.relative_to(root))
        name = p.name.lower()
        if name == "package.json":
            out += _scan_package_json(p, rel, known)
        elif name == "requirements.txt":
            out += _scan_requirements(p, rel, known)
        elif name in (".mcp.json", "mcp.json"):
            out += _scan_mcp_cmd(p, rel, known)
    return out
