from pathlib import Path
import sentinel.install as inst


def test_safe_name_sanitizes():
    assert inst._safe_name("../../etc/passwd") == "etc-passwd" or "/" not in inst._safe_name("../../etc/passwd")


def test_recommend_command_mcp():
    cmd = inst.recommend_command("mcp", "my server", "https://github.com/o/r")
    assert "claude mcp add" in cmd


def test_recommend_command_plugin():
    cmd = inst.recommend_command("plugin", "p", "https://github.com/o/r")
    assert "/plugin" in cmd


def test_install_into_tmp_records_registry(tmp_path, monkeypatch):
    # point REGISTRY at a tmp file so we don't touch the real home
    reg = tmp_path / "registry.json"
    monkeypatch.setattr(inst, "REGISTRY", reg)
    # install from the local clean fixture acting as a repo via file:// is overkill;
    # instead test the registry recorder directly:
    inst._record({"name": "demo", "repo_slug": "o/r", "sha": "abc123",
                  "band": 1, "score": 88, "judge_verdict": {"injection": False}})
    data = inst.load_registry()
    assert data and data[-1]["judge_verdict"] == {"injection": False}


def test_record_replaces_same_slug(tmp_path, monkeypatch):
    reg = tmp_path / "registry.json"
    monkeypatch.setattr(inst, "REGISTRY", reg)
    inst._record({"name": "a", "repo_slug": "o/r", "sha": "1"})
    inst._record({"name": "a", "repo_slug": "o/r", "sha": "2"})
    data = inst.load_registry()
    assert len([e for e in data if e["repo_slug"] == "o/r"]) == 1
    assert data[-1]["sha"] == "2"


def test_safe_name_rejects_dot_only():
    assert inst._safe_name("..") == "skill"
    assert inst._safe_name(".") == "skill"
    assert inst._safe_name("") == "skill"
    assert inst._safe_name("my-skill") == "my-skill"
    assert inst._safe_name("skill.v2") == "skill.v2"
