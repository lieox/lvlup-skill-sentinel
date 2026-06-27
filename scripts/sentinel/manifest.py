"""Structural parsing of high-privilege config: MCP servers, hooks, plugin manifests, agents.

These surfaces run with full user privileges (MCP stdio) or auto-fire shell (hooks), so they are
the most dangerous part of an extension. Pure stdlib JSON + regex; never executes anything.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

CRITICAL, HIGH, MED, LOW = "CRITICAL", "HIGH", "MED", "LOW"

_ENV_OR_NET = re.compile(
    r"(curl|wget|nc|/dev/tcp|https?://|\$[A-Z_]*KEY|\$[A-Z_]*TOKEN|\$[A-Z_]*SECRET|\.env)",
    re.IGNORECASE)
_SHELLY = re.compile(r"(\|\s*(ba)?sh\b|-c\b|&&|\$\()")
HOOK_EVENTS = ("PreToolUse", "PostToolUse", "SessionStart", "Stop", "SubagentStop", "Notification")


def _f(category, severity, rule, filename, snippet, line=1):
    return {"category": category, "severity": severity, "rule": rule,
            "file": filename, "line": line, "snippet": str(snippet)[:160]}


def _load(p: Path):
    try:
        return json.loads(p.read_text("utf-8", "replace"))
    except (OSError, json.JSONDecodeError):
        return None


def _scan_mcp(data, rel):
    out = []
    servers = data.get("mcpServers") or data.get("servers") or {}
    if isinstance(servers, dict):
        items = servers.items()
    elif isinstance(servers, list):
        items = [(s.get("name", "?"), s) for s in servers if isinstance(s, dict)]
    else:
        items = []
    for name, cfg in items:
        if not isinstance(cfg, dict):
            continue
        cmd = " ".join([str(cfg.get("command", ""))] + [str(a) for a in cfg.get("args", []) or []])
        is_stdio = cfg.get("type") == "stdio" or bool(cfg.get("command"))
        if is_stdio:
            sev = HIGH if _SHELLY.search(cmd) else MED
            out.append(_f("config", sev, f"stdio MCP server '{name}' (full user privileges)",
                          rel, cmd or name))
    return out


def _scan_hooks(data, rel):
    out = []
    hooks = data.get("hooks")
    if not isinstance(hooks, dict):
        return out
    for event in HOOK_EVENTS:
        for matcher in hooks.get(event, []) or []:
            for h in (matcher.get("hooks", []) if isinstance(matcher, dict) else []) or []:
                cmd = str(h.get("command", "")) if isinstance(h, dict) else ""
                if not cmd:
                    continue
                sev = HIGH if _ENV_OR_NET.search(cmd) else MED
                out.append(_f("config", sev, f"auto-firing hook ({event})", rel, cmd))
    return out


def _scan_plugin(data, rel):
    comps = [k for k in ("skills", "commands", "agents", "hooks", "mcpServers")
             if k in data and data.get(k)]
    if comps:
        return [_f("config", LOW, f"plugin bundle exposes: {', '.join(comps)}", rel, comps)]
    return []


_FM = re.compile(r"^---\s*\n(.*?)\n---", re.DOTALL)
_TOOLS = re.compile(r"^\s*(?:allowed-tools|tools)\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)


def _scan_agent_md(text, rel):
    m = _FM.search(text)
    if not m:
        return []
    fm = m.group(1)
    tm = _TOOLS.search(fm)
    if not tm:
        return []
    tools = tm.group(1).strip()
    low = tools.lower()
    broad = tools.strip() == "*" or ("bash" in low and ("webfetch" in low or "read" in low))
    if broad:
        return [_f("config", MED, "broad agent tool grant (read+exfil capable)", rel, tools)]
    return []


def scan_manifests(root: Path) -> list[dict]:
    root = Path(root)
    out = []
    for p in root.rglob("*"):
        if not p.is_file() or ".git/" in str(p):
            continue
        rel = str(p.relative_to(root))
        name = p.name.lower()
        if name in (".mcp.json", "mcp.json"):
            d = _load(p)
            if isinstance(d, dict):
                out += _scan_mcp(d, rel)
        elif name in ("settings.json", "hooks.json"):
            d = _load(p)
            if isinstance(d, dict):
                out += _scan_hooks(d, rel)
        elif name in ("plugin.json", "marketplace.json"):
            d = _load(p)
            if isinstance(d, dict):
                out += _scan_plugin(d, rel)
        elif name.endswith(".md"):
            try:
                out += _scan_agent_md(p.read_text("utf-8", "replace"), rel)
            except OSError:
                pass
    return out
