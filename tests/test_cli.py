import json
import subprocess
import sys
from pathlib import Path

SCOUT = Path(__file__).resolve().parents[1] / "scripts" / "scout.py"


def _run(*args):
    return subprocess.run([sys.executable, str(SCOUT), *args],
                          capture_output=True, text=True, timeout=60)


def test_cli_help_lists_subcommands():
    r = _run("--help")
    assert r.returncode == 0
    for sub in ("discover", "vet", "revet", "install"):
        assert sub in r.stdout


def test_cli_vet_bad_url_emits_json_error():
    r = _run("vet", "https://github.com/this-org/does-not-exist-xyz", "--ref", "nope")
    # must not crash; must emit JSON with an error field
    out = json.loads(r.stdout)
    assert out.get("error")
