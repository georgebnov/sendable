# Task runner for the Sendable skill.
#
# `just check` is the gate. It is exactly what CI runs, so a green local run
# means a green CI run. Every recipe works from the repo root.
#
# The skill itself needs no environment: a caller runs `uv run scripts/audit.py`
# and uv resolves the dependencies from the script's own header. These recipes
# are for developing the skill, not for using it.

set shell := ["bash", "-euo", "pipefail", "-c"]

# The minimum share of statements that must be covered. Raise this as coverage
# grows; never lower it to make a red run go green.
coverage_floor := "81"

# Everything. Run this before every commit.
check: lint types test

# ruff, as both linter and formatter. No file is excluded from either.
lint:
    uv run --quiet ruff check .
    uv run --quiet ruff format --check .

# mypy over engine, scripts, and the tests themselves.
types:
    uv run --quiet mypy

# The suite, with a coverage floor that fails the run if it drops.
test:
    uv run --quiet pytest -q --cov --cov-report=term --cov-fail-under={{ coverage_floor }}

# The suite with no coverage instrumentation. Faster while iterating.
test-fast:
    uv run --quiet pytest -q

# Per-file coverage, worst first, to decide where the next test goes.
coverage:
    #!/usr/bin/env bash
    set -euo pipefail
    uv run --quiet pytest -q --cov --cov-report=term 2>&1 \
      | grep -E '^(engine|scripts)' \
      | awk '{c=$NF; gsub("%","",c); print c+0"%\t"$2"\tstmts\t"$1}' \
      | sort -n

# Apply every fix ruff can make on its own, then format.
fix:
    uv run --quiet ruff check . --fix
    uv run --quiet ruff format .

# Audit one email through the real entry point, the way a caller does.
audit file *FLAGS:
    uv run scripts/audit.py "{{ file }}" {{ FLAGS }}

# Prove the packaged script runs with no project environment at all. This is the
# path a user takes, so it is the one that must not break.
smoke:
    #!/usr/bin/env bash
    set -euo pipefail
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    cp tests/fixtures/clean_bulk.eml "$tmp/mail.eml"
    cd "$tmp"
    uv run --quiet "{{ justfile_directory() }}/scripts/audit.py" mail.eml --offline 2>/dev/null > report.json
    uv run --quiet python - <<'PY'
    import json
    r = json.load(open("report.json"))
    assert 0 <= r["score"] <= 100, r["score"]
    assert r["verdict"] in {"GO", "REVIEW", "NO_GO"}, r["verdict"]
    assert r["findings"], "no findings means the fan-out did not run"
    print(f'smoke ok: score={r["score"]} verdict={r["verdict"]} findings={len(r["findings"])}')
    PY

# Model-check the DMARC policy ladder with TLC. Not part of `just check` and it
# cannot be: it needs Java, and TLC is a jar this repo does not carry. Run it
# when you change LADDER, _ladder_index, _relief_index, or dmarc_decision.
# tests/formal/README.md says what the nine rules mean.
verify:
    #!/usr/bin/env bash
    set -euo pipefail
    jar="${TLA2TOOLS:-{{ justfile_directory() }}/.tla/tla2tools.jar}"
    if [[ ! -f "$jar" ]]; then
      echo "No TLC at $jar" >&2
      echo "Get it once, into a folder git ignores:" >&2
      echo "  mkdir -p .tla && curl -fsSL -o .tla/tla2tools.jar \\" >&2
      echo "    https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar" >&2
      echo "Or set TLA2TOOLS to a copy you already have." >&2
      exit 1
    fi
    cd "{{ justfile_directory() }}/tests/formal"
    java -XX:+UseParallelGC -cp "$jar" tlc2.TLC -config Ladder.cfg -workers 1 Ladder.tla
