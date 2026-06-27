"""Decode-and-rescan layered obfuscation. Decodes base64/hex blobs (NO execution) and
re-runs the static scanners on the decoded text, up to `depth` layers."""
from __future__ import annotations

import base64
import binascii
import re

from . import patterns
from . import astscan

# A base64 blob worth decoding: long, base64 alphabet, not a normal word.
_B64 = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")
_HEX = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")
_CODE_HINT = re.compile(r"[;(){}=]|import |def |curl|wget|rm ", re.IGNORECASE)


def _find_b64_blobs(text: str) -> list[str]:
    out = []
    for m in _B64.finditer(text):
        s = m.group(0)
        # base64 length must be a multiple of 4 to decode cleanly
        if len(s) % 4 == 0:
            out.append(s)
    return out


def _try_b64(s: str):
    try:
        raw = base64.b64decode(s, validate=True)
        return raw.decode("utf-8", "strict")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


def _scan_decoded(decoded: str, filename: str) -> list[dict]:
    found = patterns.scan_text(decoded, filename)
    if _CODE_HINT.search(decoded):
        found += astscan.scan_code(decoded, filename if "." in filename else filename + ".py")
    return found


def rescan_encoded(text: str, filename: str, depth: int = 2) -> list[dict]:
    out: list[dict] = []
    layer_inputs = [text]
    for _ in range(max(1, depth)):
        next_inputs = []
        for chunk in layer_inputs:
            for blob in _find_b64_blobs(chunk):
                decoded = _try_b64(blob)
                if decoded is None or decoded == blob:
                    continue
                for f in _scan_decoded(decoded, filename):
                    f = {**f, "rule": "[decoded] " + f["rule"]}
                    out.append(f)
                next_inputs.append(decoded)  # feed deeper layers
        if not next_inputs:
            break
        layer_inputs = next_inputs
    # de-dup identical (file,line,rule)
    seen, uniq = set(), []
    for f in out:
        k = (f["file"], f["line"], f["rule"])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    return uniq
