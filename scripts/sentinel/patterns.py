"""Static red-flag patterns. Mirrors references/threat-model.md.

scan_text(text, filename) -> list[Finding]. Pure regex, no execution.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

CRITICAL, HIGH, MED, LOW = "CRITICAL", "HIGH", "MED", "LOW"


@dataclass
class Rule:
    category: str
    severity: str
    pattern: re.Pattern
    desc: str


def _r(p: str) -> re.Pattern:
    return re.compile(p, re.IGNORECASE)


def _rs(p: str) -> re.Pattern:
    """Case-sensitive (for tokens whose casing carries meaning, e.g. JS Function ctor)."""
    return re.compile(p)


# Zero-width / bidi smuggling - explicit code points (don't paste literals into source).
_ZW = _r("[​‌‍\u200E\u200F\u202A\u202B\u202C\u202D\u202E﻿]")

RULES: list[Rule] = [
    # 1 - destructive / shell-out (CRITICAL)
    Rule("destructive", CRITICAL, _r(r"rm\s+-rf?\s+(/|~|\$HOME|\*)"), "recursive force delete"),
    Rule("destructive", CRITICAL, _r(r"(curl|wget)\s+[^|\n]*\|\s*(bash|sh|zsh)"), "pipe remote payload to shell"),
    Rule("destructive", CRITICAL, _r(r":\(\)\s*\{.*\|.*&.*\};:"), "fork bomb"),
    Rule("destructive", CRITICAL, _r(r"/dev/tcp/"), "reverse shell via /dev/tcp"),
    Rule("destructive", CRITICAL, _r(r"\b(nc|ncat)\s+-e\b"), "netcat exec reverse shell"),
    Rule("destructive", CRITICAL, _r(r"unzip\s+-P\b"), "password-protected payload zip"),

    # 2 - credential / secret access (severity by how rarely-legitimate it is)
    Rule("credentials", CRITICAL, _r(r"\.ssh/id_(rsa|ed25519|ecdsa)"), "reads SSH private key"),
    Rule("credentials", CRITICAL, _r(r"\.aws/credentials"), "reads AWS credentials"),
    Rule("credentials", CRITICAL, _r(r"\bsk-[A-Za-z0-9]{20,}\b"), "hardcoded OpenAI-style key"),
    Rule("credentials", CRITICAL, _r(r"\bghp_[A-Za-z0-9]{30,}\b"), "hardcoded GitHub token"),
    Rule("credentials", HIGH, _r(r"security\s+find-generic-password|login\.keychain"), "reads macOS keychain"),
    # extremely common + usually legitimate (docs, .env.example) -> LOW (recorded, no band impact)
    Rule("credentials", LOW, _r(r"(^|[/\s\"'])\.env\b"), "references .env"),
    Rule("credentials", LOW, _r(r"\b(ANTHROPIC_API_KEY|OPENAI_API_KEY|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY)\b"), "names an env secret"),

    # 3 - prompt injection (CRITICAL) - SKILL.md / commands / tool descriptions
    Rule("prompt_injection", CRITICAL, _r(r"(do not|don'?t)\s+(tell|inform|mention|notify|alert)\b.{0,30}\b(user|him|her|them)"), "tells agent to hide from user"),
    Rule("prompt_injection", CRITICAL, _r(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|context)"), "instruction override"),
    Rule("prompt_injection", CRITICAL, _r(r"</?(IMPORTANT|SECRET|SYSTEM|HIDDEN)>"), "hidden-instruction tag"),
    Rule("prompt_injection", CRITICAL, _r(r"(append|include|add|attach)\b.{0,40}\b(api[_-]?key|token|secret|credential)\b.{0,40}\b(url|query|param|header)"), "smuggle secret into request"),
    Rule("prompt_injection", CRITICAL, _r(r"when the user\b.{0,40}\b(also|additionally|secretly|silently)\b"), "conditional covert action"),
    Rule("prompt_injection", CRITICAL, _r(r"disregard\s+(safety|guidelines|rules)"), "disable safety"),

    # 4 - exfiltration / network (HIGH)
    Rule("exfiltration", HIGH, _r(r"https?://\d{1,3}(\.\d{1,3}){3}"), "raw-IP endpoint"),
    Rule("exfiltration", HIGH, _r(r"(webhook\.site|pipedream|ngrok|requestbin|burpcollaborator)"), "known exfil sink"),
    Rule("exfiltration", HIGH, _r(r"(bit\.ly|tinyurl|t\.co|is\.gd)/"), "URL shortener sink"),
    Rule("exfiltration", HIGH, _r(r"(curl|wget)\s+(-d|--data|-F|--data-binary)\b.{0,60}\$\("), "post command output"),
    Rule("exfiltration", HIGH, _r(r"(169\.254\.169\.254|metadata\.google|computeMetadata)"), "cloud-metadata SSRF"),
    Rule("exfiltration", HIGH, _r(r"(nslookup|dig)\s+.{0,40}\$\("), "DNS exfiltration"),

    # 5 - obfuscation (HIGH)
    Rule("obfuscation", HIGH, _r(r"base64\s+(-d|--decode)|\batob\(|b64decode|from_b64"), "base64 decode"),
    Rule("obfuscation", HIGH, _r(r"(?<![\w.])(eval|exec)\s*\("), "dynamic code exec (eval/exec)"),
    Rule("obfuscation", HIGH, _r(r"child_process"), "node child_process"),
    Rule("obfuscation", HIGH, _rs(r"new\s+Function\s*\("), "JS Function constructor"),
    Rule("obfuscation", HIGH, _r(r"(\\x[0-9a-f]{2}){4,}|(\\u[0-9a-f]{4}){4,}"), "hex/unicode escape blob"),
    Rule("obfuscation", HIGH, _ZW, "zero-width / bidi smuggling"),

    # 8 - dangerous config (MED)
    Rule("config", MED, _r(r"\"headersHelper\"\s*:"), "headersHelper runs shell"),
    Rule("config", MED, _r(r"(PostToolUse|SessionStart|PreToolUse)\b.{0,80}\"command\""), "auto-firing hook command"),
]

# Files worth scanning (by name/suffix). Everything else is skipped to stay fast.
SCAN_SUFFIXES = (".md", ".py", ".js", ".ts", ".sh", ".bash", ".zsh", ".json",
                 ".yaml", ".yml", ".toml", ".rb", ".pl")
SCAN_NAMES = ("SKILL.md", ".mcp.json", "hooks.json", "settings.json",
              "marketplace.json", "plugin.json")


def should_scan(path_name: str) -> bool:
    if path_name in SCAN_NAMES:
        return True
    return path_name.lower().endswith(SCAN_SUFFIXES)


def scan_text(text: str, filename: str) -> list[dict]:
    findings = []
    lines = text.splitlines()
    for rule in RULES:
        for m in rule.pattern.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            snippet = (lines[line_no - 1].strip()[:160] if 0 < line_no <= len(lines) else m.group(0)[:160])
            findings.append({
                "category": rule.category, "severity": rule.severity,
                "rule": rule.desc, "file": filename, "line": line_no,
                "snippet": snippet,
            })
    return findings
