# docs/

Two doc trees live in this repo. Know which one you're reading.

## Live docs — `production/backend/docs/`

Current, maintained. Read these before non-trivial work:

- **`AWS_OPS.md`** — every operational knob: secret rotation, RDS password reset, scaling, cost.
- **`DMARC_PHASE_2_RUNBOOK.md`** — the live SES → S3 → SQS → DNS ingestion wiring, step by step.
- **`JULY_LAUNCH_STATUS.md`** — current product state: done vs deferred, what blocks paying users.
- **`CODE_HEALTH_AUDIT_2026_06_09.md`** — duplication, long functions, DB writes outside the service layer.
- **`SYSTEM_OVERVIEW.md`** — top-down map of the running system.
- **`SQS_LABEL_IMPORT_PLAN.md`** — label-import design notes.

## This directory — mostly historical

`BACKLOG.md` is live (tracks deferred work — keep it current). Everything else here
is PoC-era reference from the original single-user tool, untouched since the
2026-05-20 initial commit. The PoC tree was removed; it's preserved at the git
tag `poc-archive`. These describe how the PoC worked, not necessarily how
`production/` works now — treat as background, verify against code before relying on them:

- `PIPELINE.md`, `STEP1_CHECKS.md`, `CHECKS_RUBRIC.md` — PoC audit pipeline + check definitions.
- `STEP3_DRIFT_RESEARCH.md`, `STEP3_DRIFT_ROADMAP.md` — drift-detection research (Step 3, never shipped to prod).
- `DEMO.md` — old demo-prep notes.
- `MICROSOFT_SETUP.md` — Entra/Azure AD app registration (Outlook OAuth path, not the live Google flow).
- `superpowers/` — Claude Code session artifacts (plans, specs). Not product docs.
