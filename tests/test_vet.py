import os
from pathlib import Path
import pytest
from sentinel import vet

FIX = Path(__file__).parent / "fixtures"


def test_clean_tree_is_band_1():
    res = vet.scan_tree(FIX / "clean_skill")
    band, _ = vet.band_from_findings(res["findings"])
    assert band == 1
    assert res["files_scanned"] >= 2


def test_clean_tree_has_green_flags():
    res = vet.scan_tree(FIX / "clean_skill")
    assert any("allowed-tools" in g for g in res["green_flags"])


def test_malicious_tree_flags_credentials_and_injection():
    res = vet.scan_tree(FIX / "malicious_skill")
    cats = {f["category"] for f in res["findings"]}
    assert "credentials" in cats
    assert "prompt_injection" in cats


def test_malicious_tree_band_is_high():
    res = vet.scan_tree(FIX / "malicious_skill")
    band, label = vet.band_from_findings(res["findings"])
    assert band >= 4


def test_band_from_findings_two_critical_categories_is_5():
    findings = [
        {"category": "credentials", "severity": "CRITICAL"},
        {"category": "prompt_injection", "severity": "CRITICAL"},
    ]
    assert vet.band_from_findings(findings)[0] == 5


def test_band_only_med_is_2():
    findings = [{"category": "config", "severity": "MED"}]
    assert vet.band_from_findings(findings)[0] == 2


@pytest.mark.skipif(os.environ.get("SENTINEL_OFFLINE") == "1",
                    reason="network test disabled")
def test_vet_repo_known_clean_repo_does_not_raise():
    res = vet.vet_repo("https://github.com/anthropics/skills")
    assert "band" in res and res.get("error", "") == "" or res["band"] is None


def test_scan_tree_includes_manifest_findings(tmp_path):
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers": {"x": {"type": "stdio", "command": "node"}}}', encoding="utf-8")
    (tmp_path / "SKILL.md").write_text("---\nname: t\n---\nok", encoding="utf-8")
    res = vet.scan_tree(tmp_path)
    assert any(f["category"] == "config" for f in res["findings"])


def test_scan_tree_includes_supply_chain(tmp_path):
    (tmp_path / "requirements.txt").write_text("reqursts\n", encoding="utf-8")
    res = vet.scan_tree(tmp_path)
    assert any(f["category"] == "supply_chain" for f in res["findings"])
