READ ~/Projects/agent-scripts/AGENTS.md BEFORE ANYTHING (skip if missing).

# Agent guide — Sendable

An email-deliverability SaaS. The FastAPI backend (`api.sndbl.com`) runs the audit
pipeline and DMARC ingestion; the Next.js app (`app.sndbl.com`) is the product UI;
the Astro site (`sndbl.com`) is the marketing surface. All work lives under
`production/{backend,frontend,website}/`. `CLAUDE.md` in this directory is the
long-form reference; this file is the operational contract.

## Toolchain

Backend: Python 3.12, `.venv` + pip, `ruff` (lint/format), `mypy` (gated paths),
`pytest` against a real Postgres 16, `alembic` for migrations. Frontend/website: Node
+ `npx`. Deployed to AWS Fargate via the Copilot CLI (backend) and Vercel (frontend);
the website is static.

```bash
# Backend — from production/backend/ (tests need DATABASE_URL; .env has it)
set -a; source .env; set +a
.venv/bin/ruff check . && .venv/bin/ruff format --check . && .venv/bin/mypy
.venv/bin/pytest -q
.venv/bin/alembic -c db/alembic.ini upgrade head          # apply migrations locally

# Frontend — from production/frontend/
npx next lint --max-warnings=0 && npx tsc --noEmit

# Website — from production/website/
npm run build
```

## Python

- Keep code passing `mypy` on the gated paths (`app/{core,auth,services,api}` and the
  rest configured in `pyproject.toml`). Prefer explicit SQLModel/pydantic models and
  concrete field types over `Any`, bare `dict`, or untyped `**kwargs`.
- `app/domain/*` is **frozen** ported PoC code, deliberately excluded from ruff, mypy,
  and CI. Lint passes even on obviously-broken code there, so the linter will not catch
  your mistake. Touch it only when asked, and never restyle it in passing.

## Rules

1. **Clean tree before every commit.** Run the net for every stack you touched and fix
   **every** error before committing — including ones you don't think you introduced.
   Backend: `ruff check . && ruff format --check . && mypy && pytest -q`. Frontend:
   `next lint --max-warnings=0 && tsc --noEmit`. Website: `npm run build`. Never silence
   a check (`# type: ignore`, `eslint-disable`, `# noqa`) to go green — fix the cause or
   surface it. A red check is an unfinished task, not a known issue to file.

2. **Tests live in `production/backend/tests/`, called at the service level.** There is
   no FastAPI TestClient; async tests call handlers/services directly with the
   `db_session` fixture from `tests/conftest.py`. New behavior ships with tests covering
   the happy path plus at least one failure/edge case. A red suite is an unfinished task.

3. **The schema is strict and typed.** 24 tables, **zero JSONB**, all PKs `uuid`, every
   timestamp `TIMESTAMPTZ` via `sa_type=TZ`. No native ENUMs — closed sets are `TEXT` +
   a `CheckConstraint`. `ON DELETE CASCADE` on every child FK; nullable links `SET NULL`.
   Model new data the same way; don't reach for a JSON blob or an untyped column.

4. **Services own DB writes; handlers orchestrate.** An API handler mutating rows
   directly is refactor debt. The frontend never touches the DB — all data goes through
   `production/frontend/lib/api.ts` (`api<T>(path, init)`), which handles credentials and
   the 401 redirect.

5. **No new table or column without a migration in the same change.** CI catches it, but
   commit them together. Alembic autogenerate produces noise (index renames, AutoString↔
   TEXT churn) — read the generated file and strip everything that isn't your change
   before committing.

6. **Interpretation changes are data-gated.** New logic reading old rows silently skews
   the prior dataset. Any change under `app/services/`, `app/domain/audit/`, or
   `app/domain/ingest/` must either add a backfill script under
   `app/scripts/backfill/` (named `bf_<YYYYMMDD>_<slug>.py`) **or** carry the
   `no-data-impact` label set **at PR-create time** (labeling later doesn't trigger the
   gate). Make the conscious choice; ship a backwards-compat test proving old inputs
   still load correctly.

7. **Ask first before quietly changing how core logic interprets data.** The audit
   pipeline (`app/services/audit_service.py` + `app/domain/audit/`), the DMARC
   classification chain (`app/domain/audit/dmarc/`), and the iteration fuzzy match
   (`app/services/iteration_service.py`) all leave the prior dataset misaligned if their
   interpretation shifts. Surface what you're about to change before editing.

8. **Keep imports explicit and fail-fast.** Imports at module scope unless breaking a
   real circular dependency. No lazy imports for convenience, and don't catch
   `ImportError` to silently fall back to alternate behavior.

9. **Design every surface from the caller's side.** Before building a feature, write the
   call site first — the API response an app screen consumes, the `api.ts` call, the
   pydantic model — and judge it: obvious, minimal, hard to misuse? Error messages are
   part of the interface: a failure a user can hit must say what went wrong *and* what to
   do about it.

10. **Tests come before functionality.** Write the failing test first, then implement
    until it passes. Bug fixes are no exception: reproduce the bug with a failing test,
    then fix it — a fix without a captured repro can silently regress. Never weaken an
    existing test to get green; if a test encodes outdated behavior, fix or delete it and
    say why. New behavior without a test that would catch its regression is not done.

11. **Verify end-to-end before claiming done.** Unit tests passing is necessary, not
    sufficient. Deploys silently fail behind ALB health checks more often than you'd hope
    — drive the real surface (hit the endpoint, load the page, paste the CLI output) and
    confirm observed behavior, not just an exit code. When a task spans code + Fargate
    deploy + DNS/SES/RDS, verify each substep; don't assume success.

12. **Tune automated components against their real outputs.** Anything automated — the
    audit scorer, the LLM persona rebuild, the `generate` copy, an LLM judge — is tuned on
    real data, not intuition. Pull a sample of actual inputs and outputs, read them, ask
    "do I agree with what it did here?", and adjust on the disagreements. Never declare an
    automated component improved without concrete before/after examples.

13. **Build for now, not for the future — but never break existing data.** No speculative
    generality, no unused hooks, no abstractions for single-use code; the cleanest codebase
    is the one with the least code, so delete dead paths outright and migrate every caller
    in the same change. The one thing you may *not* break is stored data: this is
    production, so schema/interpretation changes keep old rows valid (see rules 5–6) rather
    than silently reinterpreting them.

14. **Deploy from a current `main`.** The frontend auto-deploys on push to `main` (Vercel);
    the backend does not. `copilot svc deploy` builds the **local working tree**, not git
    `main` — `git checkout main && git pull` first or you ship stale code. Migrations run
    inside the container, not on deploy: a code change that reads a new column without its
    migration 500s every request, so run the migration with (or right after) the deploy.

15. **Public copy and visuals follow the brand.** The product name is **Sendable**
    (`inboxhealth` survives only as internal infra — don't rename it). Frontend styling is
    plain CSS tokens, **no Tailwind**. LLM advice and marketing copy are marketer-facing:
    frame fixes in composer-UI terms (subject line, preview-text field, link URL), never
    HTML tags, CSS properties, or RFC jargon. **No em dashes in public copy** — use commas
    or periods. Follow Conventional Commits; bump the version only via `ops/bump.sh`.
