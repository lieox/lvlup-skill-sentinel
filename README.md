# skill-sentinel

Discover Claude Code extensions and statically vet their safety before you install them. It is a
Claude Code skill: a `SKILL.md` that drives an agent, plus a stdlib-only Python CLI that does the
deterministic scanning. An improved successor to
[Brain-ai-biz/skill-scout](https://github.com/Brain-ai-biz/skill-scout).

Every directory online ranks popularity. None tells you whether a skill will read your `.env` or
rug-pull after you trust it. skill-sentinel adds the missing signal: it finds the good ones and
vets them.

## The two numbers

- **Reputation score (0-100):** shown in the discovery shortlist. How much do the public signals
  (stars, freshness, publisher, license, scanner prior-art) say you can trust this? This is
  reputation, not a code audit.
- **Risk band (1-5):** shown in the safety verdict, after a clone-and-scan. 1 = looks safe,
  2 = low risk, 3 = medium risk (review manually), 4 = high risk, 5 = do not install. It is driven
  by what the scanner and the semantic judge actually found in the code and text.

## What it upgrades over skill-scout

1. **LLM semantic judge.** Beyond regex, every vet dispatches an independent text reviewer
   (`references/judge-prompt.md`) over the SKILL.md, command markdown, MCP tool descriptions, and
   hook commands, to catch prompt injection and concealment that pattern matching misses. The final
   band is `max(static band, judge-derived band)`.
2. **Deep MCP / hooks / plugin vetting.** `manifest.py` parses MCP/hooks/plugin/agent config
   structurally (tool-poisoning, auto-firing hooks that read env or hit the network, dangerous
   config), not just discovery.
3. **revet.** Re-checks an installed extension against its pinned SHA on update and scans only the
   delta, so a rug-pull becomes visible before you pull it.
4. **Supply-chain / typosquat analysis.** `supplychain.py` enumerates declared dependencies, flags
   unpinned versions, and compares names against a known-packages list to catch typosquats.

## Install

```
git clone https://github.com/lieox/skill-sentinel ~/.claude/skills/skill-sentinel
```

Then in Claude Code, ask it to "find me a skill for X" or "is this skill safe", and the skill
triggers.

## Sanity check

```
python3 ~/.claude/skills/skill-sentinel/scripts/scout.py vet https://github.com/anthropics/skills
```
The command completes and prints a JSON verdict containing a `band` (1-5) and a list of `findings`.
As of writing, vetting `anthropics/skills` returns `band: 3` because the scanner correctly flags one
dynamic `shell=True` in a test helper for manual review. That is an example of the tool working as
intended (surfacing a real-but-benign pattern for a human to confirm), not malware. Frontmatter
check:

```
python3 - <<'PY'
import re, pathlib
fm = re.match(r"^---\n(.*?)\n---", pathlib.Path("SKILL.md").read_text("utf-8"), re.DOTALL).group(1)
assert "name: skill-sentinel" in fm and "allowed-tools:" in fm and "description:" in fm
print("SKILL.md frontmatter OK")
PY
```

## Dependencies

| Dependency | Required? | Why |
|------------|-----------|-----|
| Python 3.9+ | required | runs the CLI; standard library only, no pip installs |
| git | required | shallow-clones repos into a temp sandbox for the static scan |
| `gh` CLI | optional | lifts GitHub API rate limits during discovery |
| LLM semantic judge (Task tool) | optional | runs the text reviewer during vet; there is an inline fallback |

## Honesty caveat

This is static code analysis plus public reputation signals plus a semantic review of the text. It
does not catch every dynamic behavior, and it cannot predict a rug-pull (an extension that is clean
today and turns malicious in a future update). A clean scan means "no known red flags found", not
"proven safe". The SHA-pin + revet workflow mitigates rug-pulls (it makes a malicious update
detectable on the next pull); it does not prevent them. The final call is always yours.

## License

MIT. See [LICENSE](LICENSE).
