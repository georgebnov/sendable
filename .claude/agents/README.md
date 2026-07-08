# .claude/agents — the agents' workspace

The unclean side of the work: one-off scripts, experiment runners, plans, scratchpads, drafts.
Committed so it transfers across worktrees and chats — that is the only guarantee.

Contract:
- **Outside the gate.** The nets in AGENTS.md rule 1 (`ruff`/`mypy`/`pytest` for the backend,
  `next lint`/`tsc` for the frontend, `npm run build` for the website) run against
  `production/`, not here. Nothing in this folder is held to production standards or reviewed as
  shipping code.
- **Nothing may depend on it.** `production/{backend,frontend,website}/` must never import from
  or link to anything here as if it were permanent.
- **Pruned periodically.** Anything here may be deleted at any time. When work matures, promote
  the product out — writeups → `docs/`, reusable backend code → `production/backend/app/`,
  runnable ops scripts → `ops/`, backfills → `production/backend/app/scripts/backfill/` — and
  let the scraps die here.

Layout is free-form; `scripts/` for runnable one-offs is the only suggested convention.
