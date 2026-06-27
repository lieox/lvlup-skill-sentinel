"""Tier-1 Reputation Confidence (0-100). Mirrors references/scoring-rubric.md.

This is reputation, NOT a code audit. Anything to be installed must still pass Tier-2 (vet).
"""
from __future__ import annotations

import math

from .common import Candidate, days_since

TRUSTED_OWNERS = {"anthropics", "modelcontextprotocol", "anthropic-ai", "composiohq"}
SCANNING_SOURCES = {"skills.sh", "skillsdirectory"}


def score_candidate(c: Candidate) -> Candidate:
    pts, reasons = 0.0, []

    # Popularity (max 30)
    pop = min(30.0, 12.0 * math.log10(1 + c.stars + c.installs))
    pts += pop
    if c.stars or c.installs:
        reasons.append(f"popularity {int(pop)}/30 ({c.stars} stars)")

    # Provenance (max 25)
    owner = (c.publisher or "").lower()
    if c.official or owner in TRUSTED_OWNERS:
        pts += 25; reasons.append("official/trusted source")
    elif c.verified:
        pts += 18; reasons.append("marked verified")
    elif owner:
        pts += 6
    # known scanning-source verification
    if c.verified and c.source in SCANNING_SOURCES:
        pts += 15; reasons.append("passed scanning-source review")

    # Freshness (max 20)
    if c.archived:
        reasons.append("archived (unmaintained)")
    else:
        d = days_since(c.last_updated)
        if d is None:
            pass
        elif d <= 90:
            pts += 20; reasons.append("recently updated")
        elif d <= 180:
            pts += 14
        elif d <= 365:
            pts += 8
        else:
            reasons.append("not updated in over a year")

    # Maintenance (max 10)
    if c.license:
        pts += 5; reasons.append(f"license {c.license}")
    if not c.archived and (days_since(c.last_updated) or 999) <= 180:
        pts += 5

    # Safety prior-art (max 15)
    if c.requires_code_execution is False:
        pts += 8; reasons.append("does not require code execution")
    elif c.requires_code_execution is True:
        pts -= 5; reasons.append("requires code execution")

    c.score = max(0, min(100, round(pts)))
    c.score_reason = " - ".join(reasons[:4]) if reasons else "few signals available"
    return c


def band_label(score: int) -> str:
    if score >= 80:
        return "excellent"
    if score >= 60:
        return "good"
    if score >= 40:
        return "moderate"
    return "weak/unknown"
