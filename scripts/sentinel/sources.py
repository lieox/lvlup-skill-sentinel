"""Source connectors. Each returns list[Candidate]; each is defensive (never raises).

MVP = Skills ecosystem: GitHub (firehose) + claudemarketplaces + claudeskills.info + skills.sh.
Schemas for the 3rd-party directories are mapped defensively and tightened during smoke test.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any, Optional

from .common import Candidate, http_get_json


# ----------------------------- helpers -----------------------------

def _pick(d: dict, *keys, default=None):
    """First present, non-null value among nested keys ('a.b' allowed)."""
    for k in keys:
        cur: Any = d
        ok = True
        for part in k.split("."):
            if isinstance(cur, dict) and part in cur and cur[part] is not None:
                cur = cur[part]
            else:
                ok = False
                break
        if ok and cur not in (None, ""):
            return cur
    return default


def _as_int(v) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _find_list(payload: Any) -> list:
    """Locate the list of items in an unknown JSON envelope."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for k in ("skills", "data", "results", "items", "servers", "plugins", "records"):
            v = payload.get(k)
            if isinstance(v, list):
                return v
    return []


def _norm_generic(item: dict, source: str, ecosystem: str = "skill") -> Optional[Candidate]:
    """Best-effort map of an unknown directory item -> Candidate."""
    if not isinstance(item, dict):
        return None
    name = _pick(item, "name", "skill", "title", "slug", "fullName", "full_name")
    repo = _pick(item, "repo_url", "repoUrl", "repository", "repo", "html_url",
                 "url", "github", "githubUrl", "source")
    if not name and repo:
        name = str(repo).rstrip("/").split("/")[-1]
    if not name:
        return None
    rce = _pick(item, "requires_code_execution", "requiresCodeExecution", "codeExecution")
    if isinstance(rce, str):
        rce = rce.lower() in ("true", "yes", "1")
    return Candidate(
        name=str(name),
        ecosystem=ecosystem,
        source=source,
        repo_url=str(repo or ""),
        description=str(_pick(item, "description", "summary", "tagline", "about", default="")),
        outputs=str(_pick(item, "outputs", "produces", default="")),
        stars=_as_int(_pick(item, "stars", "stargazers_count", "stargazers", "starCount", default=0)),
        installs=_as_int(_pick(item, "installs", "installCount", "downloads", "useCount",
                               "install_count", default=0)),
        last_updated=str(_pick(item, "last_updated", "updatedAt", "updated_at", "pushed_at",
                               "pushedAt", "lastCommit", default="")),
        license=str(_pick(item, "license", "license.spdx_id", "licenseId", default="")),
        publisher=str(_pick(item, "publisher", "author", "owner", "owner.login",
                            "ownerLogin", default="")),
        official=bool(_pick(item, "official", "isOfficial", default=False)),
        verified=bool(_pick(item, "verified", "isVerified", "featured", default=False)),
        requires_code_execution=rce if isinstance(rce, bool) else None,
        homepage=str(_pick(item, "homepage", "website", default="")),
        extra={"raw_keys": sorted(item.keys())[:12]},
    )


# ----------------------------- GitHub -----------------------------

def _gh_api(query: str, per_page: int) -> list[dict]:
    """GitHub repo search via authed `gh` CLI; fall back to public REST."""
    if shutil.which("gh"):
        try:
            out = subprocess.run(
                ["gh", "api", "-X", "GET", "search/repositories",
                 "-f", f"q={query}", "-f", "sort=stars", "-f", "order=desc",
                 "-f", f"per_page={per_page}"],
                capture_output=True, text=True, timeout=30,
            )
            if out.returncode == 0:
                return json.loads(out.stdout).get("items", []) or []
        except (subprocess.SubprocessError, json.JSONDecodeError, OSError):
            pass
    body = http_get_json("https://api.github.com/search/repositories",
                         params={"q": query, "sort": "stars", "order": "desc",
                                 "per_page": per_page})
    return (body or {}).get("items", []) if isinstance(body, dict) else []


def from_github(query: str, ecosystem: str = "skill", limit: int = 20) -> list[Candidate]:
    topics = {"skill": ["claude-skills", "agent-skills"],
              "mcp": ["mcp-server", "model-context-protocol"],
              "plugin": ["claude-code-plugin", "claude-plugin"],
              "command": ["claude-code", "claude-commands"]}.get(ecosystem, ["claude-skills"])
    seen: dict[str, Candidate] = {}
    kw = (query or "").strip()
    for topic in topics:
        q = f"{kw} topic:{topic}".strip()
        for it in _gh_api(q, max(5, limit // len(topics) + 3)):
            c = Candidate(
                name=str(it.get("full_name", "")).split("/")[-1] or it.get("name", ""),
                ecosystem=ecosystem, source="github",
                repo_url=it.get("html_url", ""),
                description=it.get("description") or "",
                stars=_as_int(it.get("stargazers_count")),
                last_updated=it.get("pushed_at", ""),
                license=((it.get("license") or {}).get("spdx_id") or "") if it.get("license") else "",
                publisher=(it.get("owner") or {}).get("login", ""),
                archived=bool(it.get("archived")),
                homepage=it.get("homepage") or "",
            )
            if c.name:
                seen.setdefault(c.key(), c)
    return list(seen.values())


# ----------------------- 3rd-party directories ----------------------

def from_claudemarketplaces(query: str, ecosystem: str = "skill", limit: int = 20) -> list[Candidate]:
    body = http_get_json("https://claudemarketplaces.com/api/skills")
    items = _find_list(body)[:4000]
    out = [c for it in items if (c := _norm_generic(it, "claudemarketplaces", ecosystem))]
    return out


def from_claudeskills_info(query: str, ecosystem: str = "skill", limit: int = 20) -> list[Candidate]:
    body = http_get_json("https://claudeskills.info/api/skills", params={"limit": 100})
    items = _find_list(body)
    return [c for it in items if (c := _norm_generic(it, "claudeskills.info", ecosystem))]


def from_skills_sh(query: str, ecosystem: str = "skill", limit: int = 20) -> list[Candidate]:
    body = http_get_json("https://skills.sh/api/v1/search", params={"q": query or "claude"})
    items = _find_list(body)
    return [c for it in items if (c := _norm_generic(it, "skills.sh", ecosystem))]


# Registry of enabled connectors per ecosystem (mirrors references/sources.yaml).
CONNECTORS = {
    "skill": [from_github, from_claudemarketplaces, from_claudeskills_info, from_skills_sh],
    "mcp": [from_github],          # Phase 2: + mcp_registry, pulsemcp
    "plugin": [from_github],       # Phase 2: + claude_plugins_official/community
    "command": [from_github],      # Phase 2: + awesome-claude-code csv
}
