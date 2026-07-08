---
name: ready-for-merge
description: Mandatory pre-merge gate for every PR. Runs /code-review max --fix, resolves every review comment (Greptile, human reviewers), and verifies the diff complies with AGENTS.md. Use whenever the user says a PR is ready to merge, asks to merge, or invokes /ready-for-merge.
---

# Ready for Merge

The **mandatory gate before merging any PR** in this repository. Do not merge, and do not tell
the user a PR is ready to merge, until every step below has completed and passes.

Work against the PR for the current branch (`gh pr view --json number,url,headRefName`). If no
PR exists, stop and tell the user.

## Step 1 — Code review with fixes, scaled to the PR

Look at the PR's diff (`gh pr diff <number> --stat` and the diff itself) and pick the
code-review effort level that matches its breadth and risk — don't default to the maximum:

- **low** — mechanical or single-concern changes: a flag flip, a docstring/docs edit, a
  dependency bump, a few-line fix with an obvious test.
- **medium** — a small focused change: one behavior touched across a handful of files, new
  code paths that are well covered by tests. Most small PRs land here.
- **high** — a multi-file feature, changes to shared infrastructure, or anything where a
  subtle interaction with existing callers is plausible.
- **xhigh** — large or risky PRs: core engine/provider seams, data-loss or security surface,
  broad refactors, anything hard to roll back once merged.

State the level you chose and why in one sentence, then run the `code-review` skill with args
`<level> --fix`.

Let it finish and apply its fixes before moving on. If it applied changes, re-run the project
gate afterwards (see Step 3)

## Step 2 — Resolve every review comment on the PR

Fetch **all** comments and review threads on the PR — from Cursor (bugbot), Greptile, any other
bot reviewers, and human reviewers:

```bash
gh pr view <number> --comments
gh api repos/{owner}/{repo}/pulls/<number>/comments --paginate
gh api graphql -f query='...reviewThreads(first: 100){ nodes { isResolved comments(first: 50){ nodes { author { login } body path line } } } }...'
```

For **every single comment**, without exception:

1. Read it and decide whether it is valid.
2. If valid: fix the code, then reply to the thread stating what was changed (reference the
   fix commit).
3. If invalid or out of scope: reply to the thread explaining *why* — never silently ignore it.
4. Mark the thread resolved (GraphQL `resolveReviewThread`) once addressed.

The step is done only when zero unresolved review threads remain. Re-check with the GraphQL
query above; do not assume.

## This process is iterative — wait for reviewers to react

Greptile re-reviews on every push and humans may add comments. One pass is never enough. After
each push:

1. Wait ~180s for Greptile to re-run. This harness blocks a foreground `sleep`, so run it
   backgrounded (`sleep 180` via a background shell) or schedule a wakeup, then continue.
2. Re-fetch all comments and review threads (Step 2 queries).
3. If new unresolved comments appeared, handle them as in Step 2, push, repeat from 1.
4. Exit only when a full 3-minute wait produces **zero** new comments and zero unresolved
   threads.

## Step 3 — AGENTS.md compliance

Read `AGENTS.md` in full and audit the PR's diff (`gh pr diff <number>`) against every rule.
Key checks for this repo:

- **Clean net for every stack the PR touches** (AGENTS.md rule 1). Never silence a check
  (`# type: ignore`, `eslint-disable`, `# noqa`) to go green — fix the cause.
  - Backend (`production/backend/`): `set -a; source .env; set +a` then
    `.venv/bin/ruff check . && .venv/bin/ruff format --check . && .venv/bin/mypy && .venv/bin/pytest -q`
  - Frontend (`production/frontend/`): `npx next lint --max-warnings=0 && npx tsc --noEmit`
  - Website (`production/website/`): `npm run build`
- **Tests** live in `production/backend/tests/`, called at the service level (no TestClient; async
  handlers/services with the `db_session` fixture). New behavior ships with a happy-path test plus
  at least one failure/edge case, written before the code (rules 2, 10).
- **Migrations:** no new table/column without an Alembic migration in the same change; strip
  autogenerate noise (index renames, AutoString↔TEXT churn) before committing (rule 5).
- **Data-gated interpretation changes** (rule 6): any change under `app/services/`,
  `app/domain/audit/`, or `app/domain/ingest/` needs a backfill script under
  `app/scripts/backfill/` **or** the `no-data-impact` label set **at PR-create time** (labeling
  later does not trigger the gate), plus a backwards-compat test. Ask first before changing how
  core logic interprets data (rule 7).
- `app/domain/*` is **frozen** PoC code (excluded from ruff/mypy/CI) — don't restyle it in
  passing.
- Services own DB writes; handlers orchestrate; the frontend touches data only via
  `production/frontend/lib/api.ts` (rule 4).
- No `Any`, bare `dict`, or untyped `**kwargs` where a concrete SQLModel/pydantic type fits.
  Imports at module scope, fail-fast; no `ImportError` fallbacks (rule 8).
- **Verify end-to-end** for anything with a runtime surface — drive the endpoint/page/CLI, don't
  trust exit codes (rule 11).
- **Brand & copy** (rule 15): product name is **Sendable**; plain CSS tokens, **no Tailwind**;
  marketer-facing LLM/marketing copy (composer-UI terms, not HTML/CSS/RFC jargon); **no em
  dashes** in public copy. Conventional Commits; version bumps only via `ops/bump.sh`.

Fix any violation found. Do not rationalize a violation as pre-existing if the PR touches that
code.

## Step 4 — Report

Push any fixes from Steps 1–3, then report a checklist:

- [ ] `/code-review max --fix` completed (N findings, M fixed)
- [ ] All review comments resolved (list each commenter and how their comments were handled)
- [ ] AGENTS.md audit clean (note any rules that required fixes)
- [ ] Full project gate green for every stack touched
- [ ] Final 3-minute wait after the last push produced zero new comments

Only after all boxes are checked may the PR be merged. If anything cannot be resolved, report it
as a blocker instead of merging.
