#!/usr/bin/env python3
"""skill-sentinel CLI. The SKILL.md agent calls these; output is JSON.

  python scout.py discover "<what you want>" [--eco skill] [--limit 8]
  python scout.py vet <repo_url> [--ref <branch-or-sha>]
  python scout.py revet <name>
  python scout.py install <repo_url> --name <name> [--eco skill] [--sha <sha>] [--band N] [--score N]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sentinel import install as inst   # noqa: E402
from sentinel import vet as vetmod      # noqa: E402
from sentinel import revet as rv        # noqa: E402
from sentinel.common import relevance   # noqa: E402
from sentinel.score import score_candidate, band_label  # noqa: E402
from sentinel.sources import CONNECTORS  # noqa: E402


def _emit(obj) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def cmd_discover(a) -> None:
    eco = a.eco
    connectors = CONNECTORS.get(eco, CONNECTORS["skill"])
    pool: dict[str, object] = {}
    notes = []
    for fn in connectors:
        try:
            found = fn(a.query, eco, a.limit) or []
            notes.append(f"{fn.__name__}: {len(found)}")
        except Exception as e:  # a flaky source must never sink discovery
            notes.append(f"{fn.__name__}: ERROR {type(e).__name__}")
            found = []
        for c in found:
            cur = pool.get(c.key())
            # keep the record with the most signal (prefer one with stars/desc)
            if cur is None or (c.stars + len(c.description)) > (cur.stars + len(cur.description)):
                pool[c.key()] = c

    cands = list(pool.values())
    # relevance filter only when a query is given
    if a.query.strip():
        cands = [c for c in cands if relevance(a.query, c) > 0 or c.source == "github"]
    for c in cands:
        score_candidate(c)
    cands.sort(key=lambda c: (c.score or 0, relevance(a.query, c)), reverse=True)
    if a.min_score:
        cands = [c for c in cands if (c.score or 0) >= a.min_score]
    top = cands[: a.limit]

    _emit({
        "query": a.query, "ecosystem": eco,
        "sources_hit": notes, "returned": len(top),
        "results": [{**c.to_dict(), "score_band": band_label(c.score or 0)} for c in top],
    })


def cmd_vet(a) -> None:
    verdict = vetmod.vet_repo(a.repo, a.ref)
    verdict["severity_counts"] = vetmod.severity_counts(verdict.get("findings", []))
    _emit(verdict)


def cmd_revet(a) -> None:
    _emit(rv.revet(a.name))


def cmd_install(a) -> None:
    if a.eco == "skill":
        res = inst.install_skill(a.repo, a.name, sha=a.sha, band=a.band, score=a.score)
    else:
        res = {"ok": False, "ecosystem": a.eco, "manual": True,
               "command": inst.recommend_command(a.eco, a.name, a.repo),
               "note": "MCP/plugins install is Phase 2 - run this command yourself."}
    _emit(res)


def main() -> None:
    p = argparse.ArgumentParser(prog="scout")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("discover")
    d.add_argument("query")
    d.add_argument("--eco", default="skill", choices=["skill", "mcp", "plugin", "command"])
    d.add_argument("--limit", type=int, default=8)
    d.add_argument("--min-score", dest="min_score", type=int, default=0)
    d.set_defaults(func=cmd_discover)

    v = sub.add_parser("vet")
    v.add_argument("repo")
    v.add_argument("--ref", default=None)
    v.set_defaults(func=cmd_vet)

    r = sub.add_parser("revet")
    r.add_argument("name")
    r.set_defaults(func=cmd_revet)

    i = sub.add_parser("install")
    i.add_argument("repo")
    i.add_argument("--name", required=True)
    i.add_argument("--eco", default="skill", choices=["skill", "mcp", "plugin", "command"])
    i.add_argument("--sha", default="")
    i.add_argument("--band", type=int, default=None)
    i.add_argument("--score", type=int, default=None)
    i.set_defaults(func=cmd_install)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
