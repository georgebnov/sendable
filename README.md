<!-- README.md — Project overview. Keep short. -->

# Sendable

Pre-send email deliverability audit + domain health for marketers: connect
Gmail, audit test sends, monitor SPF/DKIM/DMARC, and generate on-brand copy.
Public name **Sendable** (`sndbl.com`); `inboxhealth` survives only as internal
infra naming (Copilot app, SQS queues).

## Layout

Everything lives under `production/`:

- **`production/backend/`** — FastAPI service (Python 3.12, SQLModel + asyncpg,
  Postgres 16, AWS SQS/S3/SES). Deployed to AWS Fargate (`ca-central-1`) via
  Copilot. API at `api.sndbl.com`.
- **`production/frontend/`** — Next.js (App Router) + React + TanStack Query.
  Deployed to Vercel. App at `app.sndbl.com`.
- **`production/website/`** — marketing site.

Repo support: `ops/` (version bump + deploy scripts), `docs/` (specs + history),
`deploy/` + `production/backend/copilot/` (infra), `.github/` (CI).

## Working in this repo

Start with **[`CLAUDE.md`](CLAUDE.md)** — daily commands, architecture,
schema notes, CI gates, and conventions. Operational runbooks live in
**[`production/backend/docs/`](production/backend/docs/)** (AWS ops, DMARC
runbook, launch status).

```bash
# Backend (from production/backend/, .env provides DATABASE_URL)
set -a; source .env; set +a; .venv/bin/pytest -q
.venv/bin/ruff check . && .venv/bin/ruff format --check . && .venv/bin/mypy

# Frontend (from production/frontend/)
npx tsc --noEmit && npx next lint
```

Versioning: `./VERSION` + `production/frontend/lib/version.ts`, bumped in lockstep
via `bash ops/bump.sh {patch|minor|major}`. See [`VERSIONING.md`](VERSIONING.md).
