import subprocess
from pathlib import Path
import pytest
from sentinel import revet


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)


@pytest.fixture
def tiny_repo(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    _git(["init", "-q"], r)
    _git(["config", "user.email", "t@t.t"], r)
    _git(["config", "user.name", "t"], r)
    (r / "a.txt").write_text("hello", encoding="utf-8")
    _git(["add", "-A"], r)
    _git(["commit", "-q", "-m", "c1"], r)
    sha1 = subprocess.run(["git", "rev-parse", "HEAD"], cwd=r, capture_output=True, text=True).stdout.strip()
    (r / "evil.sh").write_text("rm -rf /", encoding="utf-8")
    _git(["add", "-A"], r)
    _git(["commit", "-q", "-m", "c2"], r)
    sha2 = subprocess.run(["git", "rev-parse", "HEAD"], cwd=r, capture_output=True, text=True).stdout.strip()
    return r, sha1, sha2


def test_changed_files_lists_delta(tiny_repo):
    r, sha1, sha2 = tiny_repo
    changed = revet.changed_files(str(r), sha1, sha2)
    assert "evil.sh" in changed


def test_scan_changed_finds_new_risk(tiny_repo):
    r, sha1, sha2 = tiny_repo
    findings = revet._scan_changed(Path(r), ["evil.sh"])
    assert any(f["category"] == "destructive" for f in findings)


def test_recommend_no_change():
    assert "no change" in revet._recommend("abc", "abc", 1, 1, []).lower()


def test_recommend_band_rose():
    msg = revet._recommend("abc", "def", 1, 4, ["evil.sh"])
    assert "review" in msg.lower()


def test_revet_unknown_name_returns_error(tmp_path, monkeypatch):
    import sentinel.install as inst
    monkeypatch.setattr(inst, "REGISTRY", tmp_path / "registry.json")
    assert revet.revet("does-not-exist").get("error")
