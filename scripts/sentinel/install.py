"""Install-on-approval + a runtime registry. SHA-pinned (rug-pull defense).

MVP installs SKILLS into ~/.claude/skills/<name>/ at the vetted commit. MCP/plugins (Phase 2)
return the recommended command to run rather than executing it. Registry lives in the host home,
not in the module, so the module stays portable.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

try:
    from zoneinfo import ZoneInfo
    _TZ = ZoneInfo("Asia/Jerusalem")
except Exception:  # tzdata missing
    _TZ = None
from datetime import datetime, timezone

from .common import normalize_repo

REGISTRY = Path.home() / ".claude" / "skill-sentinel" / "registry.json"
SKILLS_DIR = Path.home() / ".claude" / "skills"


def _now_israel() -> str:
    tz = _TZ or timezone.utc
    return datetime.now(tz).strftime("%Y-%m-%d %H:%M") + (" IDT" if _TZ else " UTC")


def _safe_name(name: str) -> str:
    # strip leading/trailing dots, spaces, and hyphens so "..", ".", "", "--" can never
    # produce a traversal-ish or empty name under ~/.claude/skills/.
    cleaned = re.sub(r"[^a-zA-Z0-9._-]", "-", name).strip("-. ")
    return cleaned or "skill"


def load_registry() -> list[dict]:
    try:
        return json.loads(REGISTRY.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return []


def _record(entry: dict) -> None:
    REGISTRY.parent.mkdir(parents=True, exist_ok=True)
    reg = load_registry()
    slug = entry.get("repo_slug")
    reg = [e for e in reg if e.get("repo_slug") != slug] + [entry]
    REGISTRY.write_text(json.dumps(reg, ensure_ascii=False, indent=2), "utf-8")


def install_skill(repo_url: str, name: str, sha: str = "", band: int | None = None,
                  score: int | None = None, dest_dir: Path | None = None,
                  verdict: dict | None = None) -> dict:
    """Clone a skill repo into ~/.claude/skills/<name> at `sha`. Returns result dict."""
    dest_root = dest_dir or SKILLS_DIR
    target = dest_root / _safe_name(name)
    res = {"ok": False, "name": name, "repo": repo_url, "sha": sha,
           "dest": str(target), "error": "", "loaded": False}

    if target.exists():
        res["error"] = f"already exists at {target}"
        return res

    tmp = tempfile.mkdtemp(prefix="sentinel-install-")
    try:
        clone = subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "clone", "--quiet", repo_url, tmp + "/r"],
            capture_output=True, text=True, timeout=120)
        if clone.returncode != 0:
            res["error"] = "clone failed"
            return res
        if sha:
            co = subprocess.run(["git", "-C", tmp + "/r", "checkout", "--quiet", sha],
                                capture_output=True, text=True, timeout=30)
            if co.returncode != 0:
                res["error"] = f"checkout {sha[:8]} failed"
                return res
        # move into place (strip .git so it's a static copy at the pinned commit)
        subprocess.run(["rm", "-rf", tmp + "/r/.git"], capture_output=True)
        dest_root.mkdir(parents=True, exist_ok=True)
        subprocess.run(["cp", "-R", tmp + "/r", str(target)], capture_output=True)
        res["ok"] = target.exists()
        # load check: does a SKILL.md exist where Claude Code will look?
        res["loaded"] = any(target.rglob("SKILL.md"))
        if res["ok"]:
            _record({
                "name": name, "ecosystem": "skill", "repo": repo_url,
                "repo_slug": normalize_repo(repo_url), "sha": sha,
                "band": band, "score": score, "dest": str(target),
                "installed_at": _now_israel(),
                "judge_verdict": verdict,
            })
        return res
    finally:
        subprocess.run(["rm", "-rf", tmp], capture_output=True)


def recommend_command(ecosystem: str, name: str, repo_url: str) -> str:
    """Phase-2 ecosystems: return the command for the user to run, don't execute it."""
    if ecosystem == "mcp":
        return f"claude mcp add --transport stdio {_safe_name(name)} -- <command-from-its-README>"
    if ecosystem == "plugin":
        return f"/plugin marketplace add {normalize_repo(repo_url)}  &&  /plugin install {_safe_name(name)}"
    return f"# manual install - see {repo_url}"
