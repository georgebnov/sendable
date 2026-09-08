# Task runner for the Sendable monorepo. Every recipe runs from the repo root;
# the per-stack recipes cd into their own tree. The gates here are exactly the
# ones CI runs (.github/workflows/ci.yml + frontend.yml), plus the website,
# which has no workflow yet.

set shell := ["bash", "-euo", "pipefail", "-c"]

backend := justfile_directory() / "production/backend"
frontend := justfile_directory() / "production/frontend"
website := justfile_directory() / "production/website"

# Run every stack's gate: lint, format, types, tests.
check: check-backend check-frontend check-website

# Backend: ruff (lint + format), mypy on the gated paths, pytest against Postgres.
check-backend:
    #!/usr/bin/env bash
    set -euo pipefail
    cd "{{ backend }}"
    if [ ! -x .venv/bin/python ]; then
        echo "production/backend/.venv is missing — python3.12 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt" >&2
        exit 1
    fi
    # Tests need DATABASE_URL (and the app needs its secrets) — .env has them.
    # Invoke tools as `python -m` so a relocated venv's stale script shebangs
    # don't matter.
    if [ -f .env ]; then set -a; . ./.env; set +a; fi
    .venv/bin/python -m ruff check .
    .venv/bin/python -m ruff format --check .
    .venv/bin/python -m mypy
    .venv/bin/python -m pytest -q

# Frontend: Prettier, ESLint via next lint, TypeScript. No test suite yet.
check-frontend:
    #!/usr/bin/env bash
    set -euo pipefail
    cd "{{ frontend }}"
    npx prettier --check .
    npx next lint --max-warnings=0
    npx tsc --noEmit

# Website: ESLint, `astro check` for types, and a real build. No test suite yet.
check-website:
    #!/usr/bin/env bash
    set -euo pipefail
    cd "{{ website }}"
    npm run --silent lint
    npm run --silent check
    npm run --silent build

# Gate, then commit everything, push, and re-sync: `just ship "fix: ..."`.
ship msg:
    #!/usr/bin/env bash
    set -euo pipefail
    just check
    cd "{{ justfile_directory() }}"
    git add -A
    git commit -m "{{ msg }}"
    git push
    git pull --ff-only
