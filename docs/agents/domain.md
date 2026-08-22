# Domain Docs

How the engineering skills should consume this repo's domain documentation when exploring the codebase.

**Layout: single-context.** One `CONTEXT.md` at the repo root, one `docs/adr/` for decisions. `netredact`
is a single Python package with one bounded context; there is no `CONTEXT-MAP.md` and no per-context
`src/*/docs/adr/`.

## Before exploring, read these

- **`CONTEXT.md`** at the repo root — the glossary and ubiquitous language.
- **`docs/adr/`** — read the ADRs that touch the area you're about to work in.
- **`docs/design/`** — existing hand-written design notes (e.g. `actions-model.md`). Not ADRs, but they
  carry the reasoning behind the current model; read them for the same reason.

If any of these don't exist, **proceed silently**. Don't flag their absence; don't suggest creating them
upfront. `/domain-modeling` (reached via `/grill-with-docs` and `/improve-codebase-architecture`) creates
them lazily when terms or decisions actually get resolved. As of this file's creation, neither
`CONTEXT.md` nor `docs/adr/` exists yet — that is expected, not a gap to fix eagerly.

## File structure

```
/
├── CONTEXT.md                  ← glossary (created lazily)
├── docs/
│   ├── adr/                    ← decisions (created lazily)
│   │   └── 0001-....md
│   └── design/                 ← existing narrative design notes
└── src/netredact/
```

## Use the glossary's vocabulary

When your output names a domain concept (in an issue title, a refactor proposal, a hypothesis, a test
name), use the term as defined in `CONTEXT.md`. Don't drift to synonyms the glossary explicitly avoids.

This repo already has strong, load-bearing terminology in its docs and code — *sanitise*, *pseudonymise*,
*rule*, *action*, *vendor*, *address class*. Prefer the spelling and sense already used in `src/netredact/`
and `docs/` over a synonym, including the British `-ise` spellings.

If the concept you need isn't in the glossary yet, that's a signal — either you're inventing language the
project doesn't use (reconsider) or there's a real gap (note it for `/domain-modeling`).

## Flag ADR conflicts

If your output contradicts an existing ADR, surface it explicitly rather than silently overriding:

> _Contradicts ADR-0007 (event-sourced orders) — but worth reopening because…_
