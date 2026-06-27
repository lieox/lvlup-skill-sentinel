"""Shared types + helpers for skill-sentinel. Stdlib only - portable, no pip deps."""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional

USER_AGENT = "skill-sentinel/0.1 (+https://github.com/lieox/skill-sentinel)"
HTTP_TIMEOUT = 20


@dataclass
class Candidate:
    """One discovered extension, normalized across every source."""
    name: str
    ecosystem: str = "skill"          # skill | mcp | plugin | command
    source: str = ""                  # which directory surfaced it
    repo_url: str = ""
    description: str = ""
    outputs: str = ""                 # what you get out of it
    stars: int = 0
    installs: int = 0
    last_updated: str = ""            # ISO date, best-effort
    license: str = ""
    publisher: str = ""               # owner / author
    official: bool = False
    verified: bool = False
    archived: bool = False
    requires_code_execution: Optional[bool] = None
    homepage: str = ""
    # filled later:
    score: Optional[int] = None       # Tier-1 reputation confidence 0-100
    score_reason: str = ""
    extra: dict = field(default_factory=dict)

    def key(self) -> str:
        """Dedupe key: prefer normalized repo, fall back to source+name."""
        r = normalize_repo(self.repo_url)
        return r or f"{self.ecosystem}:{self.name.strip().lower()}"

    def to_dict(self) -> dict:
        return asdict(self)


def normalize_repo(url: str) -> str:
    """github.com/Owner/Repo(/...|.git) -> 'owner/repo'. '' if not a github repo."""
    if not url:
        return ""
    m = re.search(r"github\.com[:/]+([^/]+)/([^/#?]+)", url, re.I)
    if not m:
        return ""
    owner, repo = m.group(1), m.group(2)
    repo = re.sub(r"\.git$", "", repo)
    return f"{owner.lower()}/{repo.lower()}"


def http_get_json(url: str, params: dict | None = None,
                  headers: dict | None = None) -> Optional[Any]:
    """GET JSON. Returns parsed body, or None on any failure (never raises)."""
    if params:
        url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                               "Accept": "application/json",
                                               **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            raw = resp.read()
            if not raw:
                return None
            return json.loads(raw.decode("utf-8", "replace"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError,
            json.JSONDecodeError, ValueError, OSError):
        return None


def http_get_text(url: str, headers: dict | None = None) -> Optional[str]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return resp.read().decode("utf-8", "replace")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
        return None


_WORD = re.compile(r"[a-z0-9]+")


def _tokens(text: str) -> set[str]:
    return set(_WORD.findall((text or "").lower()))


def relevance(query: str, cand: Candidate) -> float:
    """Crude keyword overlap of query vs name+description. 0..1."""
    q = _tokens(query)
    if not q:
        return 1.0
    hay = _tokens(f"{cand.name} {cand.description} {cand.outputs}")
    if not hay:
        return 0.0
    return len(q & hay) / len(q)


def days_since(iso: str) -> Optional[int]:
    """Days since an ISO-ish timestamp. None if unparseable."""
    if not iso:
        return None
    s = iso.strip().replace("Z", "+00:00")
    for parse in (datetime.fromisoformat,):
        try:
            dt = parse(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - dt).days
        except ValueError:
            pass
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", s)
    if m:
        dt = datetime(int(m[1]), int(m[2]), int(m[3]), tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    return None
