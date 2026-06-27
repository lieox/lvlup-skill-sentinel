# Verdict Template

> How skill-sentinel presents results. The agent fills these in and **responds in the user's
> language** (the layouts below are in English as a reference). No em-dashes. Keep it tight and
> honest.

## Discovery shortlist (Mode A)

Open with one line on what was searched and across how many sources, then a table:

| # | skill | what it does | outputs | score (1-100) | why / why not | link |
|---|-------|--------------|---------|:------------:|---------------|------|
| 1 | name  | one line     | outputs | 86           | short + / short - | url |

Close with: "Want me to deep-dive one of these and check if it's safe to install?"

## Final safety verdict (Mode B)

```
Safety check: <name>   .   <ecosystem>
Source: <repo url>   .   scanned: <date>

Risk band: <1-5>  -  <label>
Reputation score: <0-100>

What I scanned in the code (facts):
- <finding 1: file:line - what it is>
- <finding 2 ...>
(or: "no red flags found above LOW severity")

What is a reputation signal (not the code):
- <stars / freshness / publisher in one line>

Semantic judge:
- <judge verdict on the text surface: injection / concealment / secret-smuggling / tool-poisoning>
- <severity NONE/MED/HIGH/CRITICAL, with the exact quoted phrase if anything was flagged>
(or: "no manipulation found in the text surface")

Green flags:
- <license / no network / tests / official ...>

Bottom line:
<one honest sentence: install / install-with-caution / don't install>
```

## The mandatory caveat (always)

> Important: I can't promise 100% that an extension is safe. This check is static code analysis
> plus public signals plus a semantic review of the text - it does not catch every dynamic
> behavior, and it can't predict a "rug-pull" (an extension that is clean today and turns malicious
> in a future update). From my findings the risk looks like <band>. The final call is yours.

## Install-on-approval prompt

After a band 1-2 (or band 3 the user accepts):

> Want me to install it? I'll install a specific pinned version (locked SHA), record it, and
> confirm the extension loaded. If it updates later, I'll remind you to re-check before pulling the
> new version.

For band 4-5: do NOT offer install. State plainly it is not recommended and why.
