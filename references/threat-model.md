# Threat Model + Detection Checklist

> The security brain of skill-sentinel. The scanner (`scripts/sentinel/patterns.py`) mirrors
> these rules; this doc is the human-readable source of truth. Grounded in: official
> Claude Code docs (install mechanics), Snyk ToxicSkills, Invariant Labs (MCP tool-poisoning),
> MCPTox. Verified 2026-06-19.

## What a Claude Code extension can do (why this matters)

- **Skill / slash command:** invoking it does NOT auto-run its scripts. The SKILL.md / command
  text is injected into the agent's context as instructions; the *agent* then decides to call
  Bash / run a script. So the danger is **prompt-driven**: the text tells the agent to do harm.
  `allowed-tools` is the only in-band guardrail.
- **MCP server (stdio):** runs as a local process with **full user privileges** - network,
  filesystem, env vars, host shell. After the one-time trust approval, its whole tool set is live
  with no per-tool prompt.
- **Plugin:** can bundle skills + commands + agents + **hooks** + MCP servers at once. Broadest
  trust surface; no per-component approval after install.
- **Hooks (highest severity):** auto-execute shell on events (SessionStart, PostToolUse, ...)
  **without per-event confirmation** after the one-time workspace trust. Ideal covert exfil vector.

## Risk categories (severity -> Risk Band contribution)

| # | Category | Severity | What it looks like |
|---|----------|----------|--------------------|
| 1 | Destructive / shell-out | CRITICAL | `rm -rf`, `curl\|bash`, reverse shells, fork bombs |
| 2 | Credential / secret access | CRITICAL | reads `.ssh/id_rsa`, `.aws/credentials`, `.env`; hardcoded keys |
| 3 | Prompt injection | CRITICAL | "do not tell the user", "ignore previous", `<IMPORTANT>` hidden tags, "append API_KEY to url" |
| 4 | Exfiltration / network | HIGH | raw-IP POSTs, webhook.site/ngrok, `curl -d $(...)`, cloud-metadata SSRF |
| 5 | Obfuscation | HIGH | base64/hex/unicode escapes, `eval`/`exec`, fetch-then-exec, zero-width/bidi chars |
| 6 | MCP tool-poisoning | HIGH | manipulative tool descriptions, rug-pull (behavior changes after trust) |
| 7 | Auto-firing hooks | HIGH | PostToolUse/SessionStart hook whose command reads env or hits the network |
| 8 | Dangerous config | MED | `headersHelper` (runs shell), unrestricted `allowed-tools`, Bash+WebFetch combo |
| 9 | Supply-chain / typosquat | MED | name mimics a trusted publisher; unknown npm pkg in `.mcp.json`; no version pin |
| 10 | Abandonment | LOW | stale last-commit, no license, no tests, archived |

## Deep-coverage modules

skill-sentinel does not stop at discovery for the structured-config categories. Two dedicated
modules give categories `config` and `supply_chain` their own deep static coverage:

- **`scripts/sentinel/manifest.py`** parses MCP/hooks/plugin/agent configuration directly:
  `.mcp.json` and MCP `mcpServers` blocks (stdio command + args, `headersHelper`, env-var leakage),
  `hooks*.json` and `settings*.json` hook entries (auto-firing events whose `command` reads env or
  hits the network), `plugin.json`/marketplace manifests, and agent frontmatter `tools`. It maps
  findings into the `config` category at the matching severity from the table above (categories
  6, 7, 8). This is structural, not regex-on-raw-text, so it catches dangerous config that plain
  text scanning would miss.
- **`scripts/sentinel/supplychain.py`** does dependency and typosquat analysis (category 9,
  `supply_chain`): it enumerates declared dependencies (npm packages in `.mcp.json` / manifests,
  `requirements.txt`, etc.), flags unpinned versions, and compares package and publisher names
  against `references/known-packages.txt` to catch typosquats that mimic a trusted publisher.

Both run inside `vet.scan_tree` alongside the regex/AST/deobfuscation passes, and their findings
feed the same Risk Band computation. They read files only; they never execute the manifest.

## RED flags - patterns the scanner greps for

Scan: `SKILL.md`, `*.md` (commands), `scripts/**`, `.mcp.json`, `hooks*.json`, `settings*.json`, manifests.

**Destructive / shell-out (CRITICAL)**
```
rm\s+-rf\s+(/|~|\$HOME|\*)
(curl|wget)\s+[^|]*\|\s*(bash|sh|zsh)
:\(\)\s*\{.*\|.*&.*\};:                # fork bomb
/dev/tcp/                              # reverse shell
\b(nc|ncat)\s+-e\b
unzip\s+-P                             # password-protected payload zip
```

**Credential / secret access (CRITICAL)**
```
\.ssh/id_(rsa|ed25519|ecdsa)
\.aws/credentials
(^|/|\s)\.env\b
\b(ANTHROPIC_API_KEY|OPENAI_API_KEY|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY)\b
sk-[A-Za-z0-9]{20,}
ghp_[A-Za-z0-9]{30,}
(login\.keychain|security\s+find-generic-password)
```

**Prompt injection (CRITICAL) - in SKILL.md / commands / MCP tool descriptions**
```
(do not|don'?t)\s+(tell|inform|mention|notify|alert)\b.*\b(user|him|her|them)
ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|context)
</?(IMPORTANT|SECRET|SYSTEM|HIDDEN)>
(append|include|add|attach)\b.*\b(api[_-]?key|token|secret|credential)\b.*\b(url|query|param|header)
when the user\b.*\b(also|additionally|secretly|silently)\b
disregard\s+(safety|guidelines|rules)
```

**Exfiltration / network (HIGH)**
```
https?://\d{1,3}(\.\d{1,3}){3}                       # raw IP
(webhook\.site|pipedream|ngrok|requestbin|burpcollaborator)
(bit\.ly|tinyurl|t\.co|is\.gd)                        # shortener as exfil sink
(curl|wget)\s+(-d|--data|-F|--data-binary)\b.*\$\(    # posting command output
(169\.254\.169\.254|metadata\.google|computeMetadata) # cloud-metadata SSRF
(nslookup|dig)\s+.*\$\(                               # DNS exfil
```

**Obfuscation (HIGH)**
```
base64\s+(-d|--decode)|atob\(|b64decode|from_b64
\beval\s*\(|\bexec\s*\(|Function\s*\(|child_process
(\\x[0-9a-fA-F]{2}){4,}|(\\u[0-9a-fA-F]{4}){4,}
[zero-width / bidi range]              # zero-width / bidi smuggling
```

**Dangerous config (MED)**
```
"headersHelper"\s*:                                   # runs shell to mint headers
"type"\s*:\s*"stdio"                                  # local-privilege server (review the command)
(PostToolUse|SessionStart|PreToolUse).*"command"      # auto-firing hook - inspect its command
```
Plus structural checks (not regex): `allowed-tools` missing/unrestricted; `Bash` + (`WebFetch`|`Read`)
combo = read-and-exfil capability; binaries / `.sh` / password-zips unrelated to stated purpose.

## GREEN flags - raise confidence

- Permissive license declared (MIT / Apache-2.0) and present.
- Tests dir / CI present. Active maintenance (commit/release in last ~90 days).
- Official or signed (Anthropic, or a verified/known publisher with history).
- **No network calls, no shell-out, no env-var reads.**
- `allowed-tools` minimal and matches the stated purpose.
- Every file in the bundle justified by the description; no obfuscation/encoded blobs.
- MCP pinned to a known package + version (SHA-pinned source).

## Hard limits (state these honestly, always)

- This is **static analysis + reputation + a semantic text review**. It cannot catch all
  **dynamic** behavior, and it cannot predict a **rug-pull** (clean now, malicious after a future
  update).
- A clean scan means "no known red flags found", NOT "proven safe".
- Defenses we apply anyway: SHA-pin every install; record it; re-vet on update.
