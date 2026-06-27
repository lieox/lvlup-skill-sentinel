"""Tier-2 deep static vet. Shallow-clone into a temp sandbox, scan files, compute Risk Band.

SAFETY: NEVER executes cloned code. `git clone --depth 1` with hooks neutralized, then file reads
only. Temp dir removed after scanning.
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path

from . import patterns, astscan, deobfuscate, manifest, supplychain
from .common import normalize_repo

MAX_FILE_BYTES = 1_000_000
MAX_FILES = 600
CRITICAL, HIGH, MED = patterns.CRITICAL, patterns.HIGH, patterns.MED


def _git(args, cwd=None, timeout=90):
    try:
        r = subprocess.run(["git", *args], cwd=cwd, capture_output=True,
                           text=True, timeout=timeout)
        return r.returncode, (r.stdout or r.stderr)
    except (subprocess.SubprocessError, OSError) as e:
        return 1, str(e)


def _clone(repo_url, ref, dest):
    args = ["-c", "core.hooksPath=/dev/null", "clone", "--depth", "1", "--quiet"]
    if ref:
        args += ["--branch", ref]
    args += [repo_url, dest]
    code, _ = _git(args)
    if code != 0:
        return False, ""
    code, sha = _git(["rev-parse", "HEAD"], cwd=dest)
    return True, (sha.strip() if code == 0 else "")


def _green_flags(root: Path) -> list[str]:
    flags = []
    names = {p.name.lower() for p in root.rglob("*") if p.is_file()}
    if any(n.startswith("license") for n in names):
        flags.append("license present")
    if any(n in ("readme.md", "readme") for n in names):
        flags.append("README present")
    if any("test" in n for n in names):
        flags.append("tests present")
    skill = next((p for p in root.rglob("SKILL.md")), None)
    if skill:
        try:
            m = re.search(r"allowed-tools\s*:\s*(.+)", skill.read_text("utf-8", "replace"), re.I)
            if m:
                flags.append(f"allowed-tools set ({m.group(1).strip()[:50]})")
        except OSError:
            pass
    return flags


def scan_tree(root: Path) -> dict:
    root = Path(root)
    findings, n = [], 0
    for p in root.rglob("*"):
        if n >= MAX_FILES:
            break
        if not p.is_file() or ".git/" in str(p):
            continue
        if not patterns.should_scan(p.name):
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
            text = p.read_text("utf-8", "replace")
        except OSError:
            continue
        rel = str(p.relative_to(root))
        findings.extend({**f, "file": rel} for f in patterns.scan_text(text, rel))
        findings.extend({**f, "file": rel} for f in astscan.scan_code(text, rel))
        findings.extend({**f, "file": rel} for f in deobfuscate.rescan_encoded(text, rel))
        n += 1
    findings.extend(manifest.scan_manifests(root))
    findings.extend(supplychain.scan_supply_chain(root))
    seen, uniq = set(), []
    for f in findings:
        k = (f["file"], f["line"], f["rule"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    return {"findings": uniq, "files_scanned": n, "green_flags": _green_flags(root)}


def band_from_findings(findings: list[dict]) -> tuple[int, str]:
    crit_cats = {f["category"] for f in findings if f["severity"] == CRITICAL}
    has_high = any(f["severity"] == HIGH for f in findings)
    has_med = any(f["severity"] == MED for f in findings)
    if len(crit_cats) >= 2:
        return 5, "do not install"
    if crit_cats:
        return 4, "high risk"
    if has_high:
        return 3, "medium risk - review manually"
    if has_med:
        return 2, "low risk"
    return 1, "looks safe"


def severity_counts(findings: list[dict]) -> dict:
    out = {CRITICAL: 0, HIGH: 0, MED: 0, patterns.LOW: 0}
    for f in findings:
        out[f["severity"]] = out.get(f["severity"], 0) + 1
    return out


def vet_repo(repo_url: str, ref: str | None = None) -> dict:
    result = {"repo": repo_url, "repo_slug": normalize_repo(repo_url), "ref": ref,
              "sha": "", "ok": False, "band": None, "band_label": "",
              "files_scanned": 0, "findings": [], "green_flags": [], "error": ""}
    if not repo_url:
        result["error"] = "no repo url"
        return result
    tmp = tempfile.mkdtemp(prefix="sentinel-")
    dest = os.path.join(tmp, "src")
    try:
        ok, sha = _clone(repo_url, ref, dest)
        if not ok:
            result["error"] = "clone failed (private / missing / network?)"
            return result
        result["sha"] = sha
        scanned = scan_tree(Path(dest))
        band, label = band_from_findings(scanned["findings"])
        result.update(ok=True, band=band, band_label=label, **scanned)
        return result
    finally:
        subprocess.run(["rm", "-rf", tmp], capture_output=True)
