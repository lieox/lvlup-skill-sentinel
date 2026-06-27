---
name: skill-sentinel
description: >-
  Discover the best Claude Code extensions on the web AND tell the user how safe each one is before
  installing. Reads the user's Claude Code setup, asks a few sharp questions, then surfaces a ranked
  shortlist with a 0-100 reputation score per candidate. On a chosen extension it runs a deep static
  safety scan, ALWAYS runs an independent LLM semantic judge over the text surface, and returns a
  final 1-5 risk band (always caveated). Installs on approval, SHA-pinned, and re-vets on update via
  `revet`. Covers Skills, MCP servers, plugins, and slash commands; MCP/hooks/plugin config and
  dependency typosquats are statically vetted, not just discovered. Make sure to use this skill
  whenever the user wants to find, recommend, choose, evaluate, vet, audit, or check the safety of
  any Claude Code skill / MCP server / plugin / command, even if they don't say the word "vet" -
  e.g. "find me a skill for X", "recommend a skill", "which skill should I use", "is this skill
  safe", "vet this extension", "check this MCP", "is it safe to install this plugin", "re-check for
  updates", "מצא לי סקיל", "תמליץ לי על סקיל", "האם הסקיל הזה בטוח", "תבדוק את ה-MCP הזה",
  "/skill-sentinel".
allowed-tools: Bash, Read, Glob, Grep, WebFetch, WebSearch, Task, AskUserQuestion
---

# skill-sentinel

The safety layer for growing your Claude Code setup. Every directory online ranks **popularity**;
none tells you whether an extension will read your `.env`, or rug-pull after you trust it.
skill-sentinel adds the missing signal: it finds the good ones **and vets them**, combining a
deterministic static scan, public-reputation signals, and an LLM semantic judge that reads the
extension's text surface the way a careful human reviewer would.

`SKILL_DIR` below = the folder this file lives in. Run the CLI as
`python3 SKILL_DIR/scripts/scout.py ...` (no `cd` needed). It is Python 3.9+ standard library only.
Requires Python 3.9+ and git; the `gh` CLI is optional (it lifts GitHub rate limits) and the Task
tool is optional (used for the semantic judge; there is an inline fallback).

## Golden rules (never break)

These exist because the whole value of this skill is honest safety judgement. If you cut a corner
here, the tool becomes worse than useless: it gives false confidence.

1. **Never promise "safe".** This is static analysis + reputation + a semantic text review, not a
   proof. Always give the mandatory caveat from `references/verdict-template.md`, and always
   separate "**what I scanned in the code**" (facts) from "**what is a reputation signal**"
   (inference about trust, not the code).
2. **Never install without explicit approval**, and **never offer install for band 4-5.** For those
   bands, state plainly that it is not recommended, and why, in one clear line.
3. **SHA-pin every install** and record it, so a future update can be re-vetted. This is the
   rug-pull defense: it does not prevent a rug-pull, it makes one detectable on the next pull.
4. **Respond in the user's language** (Hebrew or English, matching how they wrote to you). No
   em-dashes anywhere: use a regular hyphen, comma, or colon.
5. **The vetter never runs the cloned code.** The scan is file-reads only inside a temp sandbox.
   Do not work around that, and do not execute anything from a repo you are vetting.

---

## Mode A - Discover ("find me a skill for...")

Use when the user wants ideas, or has a goal but not a specific repo.

**1. Understand them first (do not ask what you can read).**
Skim their Claude Code setup: `CLAUDE.md`, any memory file, recent history, installed extensions.
Form a one-line hypothesis of what they do and where an extension could help.

**2. Ask 2-4 sharp questions** (use AskUserQuestion). Pick what is actually unclear:
- General sweep, or a specific idea in mind?
- The goal behind it (what would "great" look like)?
- Which ecosystems are in scope: Skills / MCP servers / plugins / commands? (default: all)
- Any hard constraints (no cloud, no API key, must be free)?

**3. Translate intent to English search terms.** The directories are English-indexed, even when the
user writes in Hebrew. Search in English; answer in their language.

**4. Run discovery** (once per ecosystem in scope):
```
python3 SKILL_DIR/scripts/scout.py discover "<english query>" --eco skill --limit 8
```
`--eco` is one of skill | mcp | plugin | command. It returns JSON: ranked candidates, each with
`score` (0-100 Tier-1 reputation), `score_band`, stars, source, repo_url, and where available a
`requires_code_execution` flag. A flaky source never sinks the run; the `sources_hit` field tells
you which directories answered, so if one returned nothing, say so rather than implying full
coverage.

**5. Present the shortlist** per `references/verdict-template.md` (a table: # / name / what it does /
outputs / score 1-100 / why or why-not / link), in the user's language. State plainly that the
score is **reputation, not a code audit**. Close by offering a deep vet on any of them.

---

## Mode B - Vet ("is this safe?")

Use when the user names a specific extension, or picks one from the shortlist. This is the hybrid
core: a deterministic scanner plus a semantic judge, merged into one band.

**1. Run the deep static scan:**
```
python3 SKILL_DIR/scripts/scout.py vet <repo_url> [--ref <branch-or-sha>]
```
It shallow-clones the repo into a temp sandbox with hooks neutralized, reads files only, scans with
regex + AST + deobfuscation + manifest (MCP/hooks/plugin/agent config) + supply-chain/typosquat
passes, then deletes the sandbox. Returns JSON: `band` (1-5), `band_label`, `sha` (the exact commit
scanned), `findings` (category / severity / file:line / snippet), `green_flags`, `severity_counts`.

**2. ALWAYS run the semantic judge** (the LLM half of the hybrid; never skip it, even on a clean
static scan, because injection lives in prose that regex misses).
- Gather the **text surface** of the repo: the `SKILL.md`, any command markdown, MCP tool
  descriptions (from `.mcp.json` / server manifests), and hook commands (from `hooks*.json` /
  `settings*.json`). Fetch them from raw GitHub URLs for the scanned `sha`, or `git show`.
- **Dispatch a Task** (a general-purpose subagent) whose instructions are the exact contents of
  `references/judge-prompt.md`, with the gathered text appended. The judge reads and judges text
  only; it never executes anything. Parse its JSON reply
  (`injection / concealment / secret_smuggling / tool_poisoning / severity / quotes / one_line`).
- **If the Task tool is unavailable,** do the judge review inline yourself: read
  `references/judge-prompt.md`, apply it to the same gathered text, and produce the same JSON
  verdict. Do not skip the judge just because Task is missing.

**3. Compute the final band** = `max(static band, judge-derived band)`, where the judge band is:
CRITICAL -> at least 4, HIGH -> at least 3, MED -> at least 2, NONE -> no change. The
`references/scoring-rubric.md` documents this rule; the band can only go up from the judge, never
down.

**4. For band 3+ or any HIGH/CRITICAL static finding, do not just relay the scanner.** Read the
actual flagged lines (fetch the file: raw GitHub URL or `git show`) and confirm real-vs-false-
positive before reporting. The scanner is deliberately trigger-happy; your job is to confirm intent.
For borderline trust, escalate reputation: a quick WebSearch / WebFetch on the publisher and repo
(or a research subagent) for incidents, age, and who they are.

**5. Give the final verdict** per `references/verdict-template.md`: the risk band + label, the
**code facts**, the **reputation signal**, the **semantic-judge result** (its verdict plus the exact
quoted phrase if it flagged anything, or "no manipulation found in the text surface"), the green
flags, one honest bottom-line sentence, and the **mandatory caveat**. You may collapse to a 1/2/3
shorthand (see the rubric) but keep the underlying 1-5 band in any record.

---

## Install on approval (only after a vet)

For **band 1-2** (or band 3 the user explicitly accepts after your review):
```
python3 SKILL_DIR/scripts/scout.py install <repo_url> --name <name> --sha <sha> --band <N> --score <C>
```
This clones the **exact vetted commit** into `~/.claude/skills/<name>/`, strips `.git` (static
copy), records it (including the judge verdict) in `~/.claude/skill-sentinel/registry.json`, and
reports whether a `SKILL.md` loaded. Then tell the user: it is pinned to `<sha>`; if it updates
later, ask skill-sentinel to re-vet before pulling the new version.

- **MCP servers / plugins:** `install` returns the exact recommended command (e.g. `claude mcp add`
  / `/plugin install`) for the user to run. It does **not** auto-execute these. Hand over the
  command plus your verdict; never run it silently.
- **band 4-5:** never offer install. State that it is not recommended, and why, in one clear line.

---

## Re-vet on update ("re-check for updates")

```
python3 SKILL_DIR/scripts/scout.py revet <name>
```
This looks up the pinned SHA in the registry, fetches the current HEAD, and scans only the delta.
Present: what changed, whether the risk band moved, and a clear pull / do-not-pull recommendation.
A band that climbed after an update is the classic rug-pull signal: call it out plainly and advise
against pulling until the user understands the change.

---

## Honesty discipline

- Mark every claim: scanned-in-code (fact) vs reputation-signal (inference).
- "Clean scan" = "no known red flags found", **not** "proven safe". Say it that way.
- If a source failed or returned nothing (a flaky directory, a private repo, no network), say so;
  do not imply full coverage.
- The semantic judge reduces missed prose-based injection, but it is still a judgement over text,
  not a runtime guarantee.

## Scope notes

- **Skills** are fully covered: discover + vet + install. **MCP servers, plugins, and commands**:
  discovery works now, and their **config is statically vetted** by `manifest.py` (tool-poisoning,
  auto-firing hooks, dangerous config) and `supplychain.py` (dependency typosquats). Auto-install
  for MCP/plugins is intentionally manual: you hand the user the command. Be honest about that
  boundary when asked.
- Detection rules live in `references/threat-model.md`; the two scoring numbers in
  `references/scoring-rubric.md`; the output layout and mandatory caveat in
  `references/verdict-template.md`; the judge instructions in `references/judge-prompt.md`; the
  discovery sources in `references/sources.yaml`. Read the relevant one when unsure how a result was
  reached.

## The mandatory caveat (state it on every verdict)

> Important: I can't promise 100% that an extension is safe. This check is static code analysis plus
> public signals plus a semantic review of the text. It does not catch every dynamic behavior, and
> it can't predict a "rug-pull" (an extension that is clean today and turns malicious in a future
> update). From my findings the risk looks like <band>. The final call is yours.
