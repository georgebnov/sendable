# CLAUDE.md

**Read [`AGENTS.md`](./AGENTS.md) first — it is the operational contract** (toolchain,
the net to run before finishing, and the numbered rules). It applies to every agent,
Claude Code included. This file is the long-form reference AGENTS.md points back to:
architecture, schema notes, the deploy runbook, CI gates, and the docs worth reading.
When the two overlap, AGENTS.md wins — keep behavioral rules there, detail here.

## Where to work

All work happens in **`production/backend/` + `production/frontend/`** — the live system, deployed at `api.sndbl.com` + `app.sndbl.com`.

(The original single-user PoC that used to live at the repo root has been removed — it was fully ported into `production/` and is preserved at the git tag `poc-archive` if ever needed.)

Inside `production/backend/`, `app/domain/*` is the ported PoC logic — **frozen**. It's deliberately excluded from ruff, mypy, and the CI gates (see `pyproject.toml`). Touch it only when asked, and don't try to refactor it for style.

## Stack

**Backend** — Python 3.12, FastAPI, SQLModel + SQLAlchemy + asyncpg, Postgres 16, AWS SQS, AWS S3 + SES inbound for DMARC ingestion. Deployed to AWS Fargate (`ca-central-1`) via the AWS Copilot CLI.

**Frontend** — Next.js (App Router) + React + TanStack Query + plain CSS tokens (no Tailwind). Deployed to Vercel.

**Auth** — Google OAuth web flow, signed httpOnly session cookie scoped to `.sndbl.com` so `app.` + `api.` share it. Tokens encrypted at rest with Fernet.

## Daily commands

All from `production/backend/` unless noted. Tests need `DATABASE_URL` exported — the `.env` file at the same dir level has it for local dev.

```bash
# Run the full test suite (needs Postgres + the env vars from .env)
set -a; source .env; set +a; .venv/bin/pytest -q

# Single test
.venv/bin/pytest tests/test_dmarc_setup.py::test_token_hex_shape -q

# Lint + format check (ruff)
.venv/bin/ruff check . && .venv/bin/ruff format --check .

# Auto-fix + format
.venv/bin/ruff check --fix . && .venv/bin/ruff format .

# Type check (gated paths only — see pyproject.toml for which)
.venv/bin/mypy

# Apply migrations (local)
.venv/bin/alembic -c db/alembic.ini upgrade head

# Generate a new migration from model diffs
.venv/bin/alembic -c db/alembic.ini revision --autogenerate -m "short_description"
```

Frontend (from `production/frontend/`):

```bash
npx tsc --noEmit          # typecheck
npx next dev              # local dev server on :3000
npx next build --no-lint  # production build (Vercel runs this too)
```

## Run the net before finishing

There are three layers — formatter, linter, type checker — wired into CI on both
stacks. **After changing code, run the layers for the stack you touched and fix
every error before you call the task done.** Never suppress (no blanket `# type: ignore`,
`eslint-disable`, or `# noqa`) to silence a check — fix the cause, or surface it if
you can't. A red check is an unfinished task, not a known issue to file.

```bash
# Backend — from production/backend/ (the same checks CI runs, in order):
.venv/bin/ruff check . && .venv/bin/ruff format --check . && .venv/bin/mypy

# Frontend — from production/frontend/:
npx next lint --max-warnings=0 && npx tsc --noEmit
```

The `.githooks/pre-commit` hook runs these automatically for whichever stack a
commit touches (enable once per clone with `git config core.hooksPath .githooks`).

## Deploy

The frontend deploys automatically on every push to `main` (Vercel hook). The backend does not. From `production/backend/`:

```bash
copilot svc deploy --name api --env prod              # FastAPI service
copilot svc deploy --name audit-worker --env prod     # SQS consumer
copilot job deploy --name poll-bucket --env prod      # 1-min Gmail poll cron
copilot job deploy --name persona-rebuild --env prod  # daily LLM persona update
```

Migrations run inside the container, NOT on deploy:

```bash
copilot svc exec -a inboxhealth -e prod -n api \
  --command "bash -lc 'cd /app && alembic -c db/alembic.ini upgrade head'"
```

If a code change adds a new column the app reads but no migration runs, the api 500s on every request. Always run migration before / right after a schema-touching deploy.

For full step-by-step ops including secret rotation, RDS password reset, scaling, and cost breakdown, read `production/backend/docs/AWS_OPS.md`.

## Versioning

Single source of truth in `./VERSION` and `production/frontend/lib/version.ts`. Bump them in lockstep via the script — never edit by hand:

```bash
bash ops/bump.sh patch    # 0.31.0 -> 0.31.1   bug fix
bash ops/bump.sh minor    # 0.31.0 -> 0.32.0   new feature
bash ops/bump.sh major    # 0.31.0 -> 1.0.0    breaking / milestone
```

The script writes both files + commits `chore: bump version to X.Y.Z`. See `VERSIONING.md` for the convention (which commit prefix → which bump).

`1.0.0` is reserved for the first paying customer + end-to-end working without babysitting.

## Architecture, top-down

```
Internet
   │
   ▼
ALB (api.sndbl.com, HTTPS via ACM)
   │
   ▼
Fargate "api" (FastAPI, 1 task)  ───────►  RDS Postgres (24 tables)
                                  ├─sends─►  SQS inboxhealth-audit
                                  └─sends─►  SQS inboxhealth-report  (legacy, retired — see polling_service docstring)

Fargate "audit-worker" (always-on, 1 task)
   │
   └─ asyncio.gather:
        consume(inboxhealth-audit)         → Gmail fetch → ingest_one_raw → emails row
        consume_dmarc_ingest(inboxhealth-dmarc-ingest) → handle_s3_event → ingest_dmarc_eml

Scheduled jobs (Copilot, separate Fargate task per fire):
   poll-bucket    (@every 1m) → polls each user's +audit Gmail alias, enqueues to inboxhealth-audit
   persona-rebuild (@daily)    → walks every user, gated LLM rebuild of UserPersona

SES inbound on ag.sndbl.com:
   MX → SES rule writes raw .eml to S3 (inboxhealth-dmarc-reports-prod/raw/<id>)
   S3 event → SQS inboxhealth-dmarc-ingest → audit-worker (above)
```

Important: the SES → S3 → SQS DMARC path is fully push-based. It does NOT depend on Gmail polling being enabled. The two paths are independent.

## Schema notes

- 24 tables, **zero JSONB**, all PKs are `uuid`, every timestamp is `TIMESTAMPTZ` via `sa_type=TZ` from `db/models/_base.py`.
- No native ENUMs — closed sets are `TEXT` + a `CheckConstraint` in `__table_args__`.
- ON DELETE CASCADE on every child FK; nullable links use SET NULL.
- `poll_queue.result_id` is a polymorphic uuid without FK (discriminated by `tag_type`).
- Migrations are alembic — autogenerate often picks up irrelevant churn (index renames, `AutoString` vs `TEXT` flips). Always read the generated file and strip the noise before committing.

## CI gates

Three workflows run on every push / PR touching `production/backend/`:

1. **`CI Checks`** (`.github/workflows/ci.yml`) — runs ruff, ruff format --check, mypy, then pytest against a real Postgres 16 service. Migrations run before tests.
2. **`Data migration check`** (`.github/workflows/data-migration-check.yml`) — if a PR touches `app/services/`, `app/domain/audit/`, or `app/domain/ingest/`, it MUST either add a script under `app/scripts/backfill/` OR carry the `no-data-impact` label. Catches "code change silently reinterprets existing rows."
3. **CodeQL** — security scan.

The data-migration gate exists because there is no "auto-fix-all-old-rows" hook. New interpretation logic + old rows = silent skew. Always make the conscious choice.

Backfill script naming: `bf_<YYYYMMDD>_<slug>.py` (the `bf_` prefix is required — module names can't start with a digit). See `app/scripts/backfill/README.md` for the conventions + one-off run pattern.

## Conventions

- **Commits** follow Conventional Commits (`feat:`, `fix:`, `chore:`, `refactor:`, etc.). The version bump rule keys off the prefix — see `VERSIONING.md`.
- **Services own DB writes.** API handlers should orchestrate; if a handler is mutating rows directly, that's refactor backlog. See `production/backend/docs/CODE_HEALTH_AUDIT_2026_06_09.md` for the in-progress audit of where this rule is broken today.
- **Tests prefer service-level calls over HTTP mocking.** There's no FastAPI TestClient in the suite — async tests call handlers / services directly with the `db_session` fixture from `tests/conftest.py`.
- **Frontend doesn't talk to the DB.** All data goes through `production/frontend/lib/api.ts` (`api<T>(path, init)`), which handles credentials + 401-redirect.
- **Page split is for prefetch, not for naming.** A data-heavy landing route splits into a server `page.tsx` that prefetches + dehydrates its queries (`apiServer` + `HydrationBoundary`) and a client island `<Route>Client.tsx` — so the page paints with data on first load instead of blank-then-fetch (see `app/(app)/dmarc/page.tsx` + `DmarcClient.tsx`). Routes with nothing worth prefetching (forms, uploads, settings, sign-in) stay a single `'use client'` `page.tsx`. Don't add a `Client.tsx` wrapper just for symmetry — an empty server wrapper is ceremony, not convention.
- **No new tables / columns without a migration in the same PR.** The CI gate will catch you, but the friendlier path is to commit them together.

## How the global rules express themselves here

(The global behavioral rules in `~/.claude/CLAUDE.md` apply everywhere. This section just notes where they bite differently in this repo.)

- **Rule 7 (Tests With Every Change)** — schema / interpretation changes are doubly gated. The data-migration CI workflow forces a backfill script OR the `no-data-impact` label for any PR touching `app/services/`, `app/domain/audit/`, or `app/domain/ingest/`. A schema-or-interpretation change without an accompanying backwards-compat test in `tests/` will pass CI but should not.
- **Rule 6 (Continuous Micro-Cleanup)** — fine in `production/backend/app/{core,auth,services,api}` and `production/frontend/`. NOT fine in `production/backend/app/domain/*` — that tree is ported PoC code held to no style or type rules. If you "clean it up" in the same pass, you'll trip lint everywhere downstream. Touch domain only when asked, and only for the asked change.
- **Rule 3 (Surgical Changes)** — alembic autogenerate produces noisy diffs (index renames, AutoString vs TEXT churn). Strip those from the migration before committing. They're not "your change."
- **Rule 4 (Goal-Driven Execution)** — when a task spans backend code + Fargate deploy + DNS / SES / RDS, the "verify" step on each substep is usually a paste of CLI output. Don't move to the next step on assumed success; deploys silently fail behind ALB health checks more often than you'd hope.
- **Rule 1 (Think Before Coding)** — three places in this repo have an unusually high "ask first" cost: the audit pipeline (`app/services/audit_service.py` + `app/domain/audit/`), the DMARC classification chain (`app/domain/audit/dmarc/`), and the iteration grouping fuzzy match (`app/services/iteration_service.py`). Quietly changing how any of these interpret data leaves the prior dataset misaligned with the new logic — see Rule 7. Surface what you're about to change BEFORE editing.

## Documents worth reading before non-trivial changes

- `production/backend/docs/AWS_OPS.md` — every operational knob, including secret rotation and RDS password reset
- `production/backend/docs/JULY_LAUNCH_STATUS.md` — current product state, what's done vs deferred, what blocks paying users
- `production/backend/docs/DMARC_PHASE_2_RUNBOOK.md` — step-by-step for the SES + S3 + SQS + DNS wiring (the live ingestion path)
- `production/backend/docs/CODE_HEALTH_AUDIT_2026_06_09.md` — duplication, long functions, DB writes outside the service layer
- `VERSIONING.md` — bump rules
- `production/LAUNCH.md` — stale May launch plan that still references App Runner; the live setup uses Fargate. Read for historical context only.

## Watch out

- `app/domain/*` looks like normal Python but is held to no style or type rules. Lint will pass even on obviously-broken code there. Don't assume the linter will catch your mistake.
- The `inboxhealth-report` SQS queue still exists on AWS but is unused — the `+report@gmail.com` polling path was retired (see the `polling_service.py` docstring). Don't rewire workers to consume it.
- Running pytest without sourcing `.env` first will fail with `KeyError: 'DATABASE_URL'` from `tests/conftest.py`. The Postgres service must also be running.
- AWS Copilot's `autogenerate` for `alembic` revisions often produces churn unrelated to your change. Always strip the noise from the generated migration file before committing.
