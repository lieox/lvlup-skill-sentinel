"""Re-vet on update (rug-pull defense). Diff the current HEAD against the pinned SHA, scan only
the changed files, and report whether the risk band moved. Never executes the repo."""
from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from . import vet, patterns, astscan, deobfuscate, manifest, supplychain
from . import install as inst


def changed_files(repo_dir: str, pinned_sha: str, head_sha: str) -> list[str]:
    try:
        r = subprocess.run(["git", "diff", "--name-only", f"{pinned_sha}..{head_sha}"],
                           cwd=repo_dir, capture_output=True, text=True, timeout=30)
        return [ln for ln in r.stdout.splitlines() if ln.strip()]
    except (subprocess.SubprocessError, OSError):
        return []


def _scan_changed(root: Path, files: list[str]) -> list[dict]:
    out = []
    for rel in files:
        p = root / rel
        if not p.is_file() or not patterns.should_scan(p.name):
            continue
        try:
            text = p.read_text("utf-8", "replace")
        except OSError:
            continue
        out.extend({**f, "file": rel} for f in patterns.scan_text(text, rel))
        out.extend({**f, "file": rel} for f in astscan.scan_code(text, rel))
        out.extend({**f, "file": rel} for f in deobfuscate.rescan_encoded(text, rel))
    # manifest + supply-chain are cheap whole-tree scans; include them too
    out.extend(manifest.scan_manifests(root))
    out.extend(supplychain.scan_supply_chain(root))
    return out


def _recommend(pinned, head, old_band, new_band, changed) -> str:
    if head == pinned:
        return "no change - safe to keep the pinned version"
    if new_band > (old_band or 1):
        return f"review - {len(changed)} files changed, band rose to {new_band}"
    return f"changed but band stable ({new_band}) - your call"


def revet(name: str) -> dict:
    reg = inst.load_registry()
    entry = next((e for e in reg if e.get("name") == name), None)
    if not entry:
        return {"error": "not in registry", "name": name}
    repo = entry.get("repo", "")
    pinned = entry.get("sha", "")
    old_band = entry.get("band")
    tmp = tempfile.mkdtemp(prefix="sentinel-revet-")
    dest = os.path.join(tmp, "src")
    try:
        c = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "clone", "--quiet", repo, dest],
                           capture_output=True, text=True, timeout=120)
        if c.returncode != 0:
            return {"error": "clone failed", "name": name}
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=dest,
                              capture_output=True, text=True).stdout.strip()
        changed = changed_files(dest, pinned, head) if pinned else []
        findings = _scan_changed(Path(dest), changed) if changed else []
        new_band, label = vet.band_from_findings(findings)
        return {"name": name, "pinned_sha": pinned, "head_sha": head,
                "changed_files": changed, "old_band": old_band, "new_band": new_band,
                "band_label": label, "band_moved": new_band != (old_band or new_band),
                "findings": findings,
                "recommendation": _recommend(pinned, head, old_band, new_band, changed)}
    finally:
        subprocess.run(["rm", "-rf", tmp], capture_output=True)
