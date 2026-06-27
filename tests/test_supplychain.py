import json
from pathlib import Path
from sentinel.supplychain import (scan_supply_chain, typosquat_check, known_packages)


def _write(tmp_path, rel, content):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def test_known_packages_loaded():
    kp = known_packages()
    assert "requests" in kp and "react" in kp


def test_typosquat_detects_near_miss():
    kp = {"requests", "react"}
    assert typosquat_check("reqursts", kp) == "requests"
    assert typosquat_check("reqeusts", kp) == "requests"


def test_typosquat_ignores_exact_and_distant():
    kp = {"requests"}
    assert typosquat_check("requests", kp) is None
    assert typosquat_check("flask", kp) is None


def test_package_json_typosquat_flagged(tmp_path):
    _write(tmp_path, "package.json", json.dumps({
        "dependencies": {"reqursts": "^1.0.0", "react": "18.2.0"}
    }))
    f = scan_supply_chain(tmp_path)
    assert any("typosquat" in x["rule"].lower() for x in f)


def test_requirements_unpinned_flagged(tmp_path):
    _write(tmp_path, "requirements.txt", "requests\nflask==2.0.0\n")
    f = scan_supply_chain(tmp_path)
    assert any("unpinned" in x["rule"].lower() and "requests" in x["rule"] for x in f)


def test_mcp_npx_package_parsed(tmp_path):
    _write(tmp_path, ".mcp.json", json.dumps({
        "mcpServers": {"x": {"command": "npx", "args": ["-y", "reqursts-mcp"]}}
    }))
    # 'reqursts-mcp' is not a near-miss of a known pkg, so no typosquat; just ensure no crash
    assert isinstance(scan_supply_chain(tmp_path), list)


def test_clean_repo_no_findings(tmp_path):
    _write(tmp_path, "requirements.txt", "requests==2.31.0\n")
    assert scan_supply_chain(tmp_path) == []
