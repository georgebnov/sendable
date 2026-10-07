READ ~/Projects/agent-scripts/AGENTS.md BEFORE ANYTHING (skip if missing).

# Agent guide — Sendable

An email deliverability audit tool, packaged as a skill an agent downloads and
runs. No service, no account, no database. `SKILL.md` is the contract an agent
reads; this file is the operational contract for working on the code.

`production/` still holds the SaaS this was refactored from: a FastAPI backend on
Fargate, a Next.js app on Vercel, and an Astro marketing site. The AWS account is
closed and none of it runs. It is excluded from every gate and is pending removal.
The state before the refactor is tagged `saas-final`, so anything there can be
recovered with `git show saas-final:<path>`.

## Layout

```
SKILL.md          the agent-facing contract. Update it when a flag or output changes.
scripts/          the three entry points. Each declares its own dependencies.
  audit.py          grade one email
  dmarc.py          ingest aggregate reports, report the next step
  reports.py        read what the store already holds
engine/           every check. No database, no network state, no globals it owns.
store/            JSON files on disk. One per audit, one per DMARC report.
tests/            the suite. No network, no model call, no database.
docs/             reference material: CHECKS_RUBRIC.md and STEP1_CHECKS.md explain
                  every check with its thresholds.
```

## Toolchain

Python 3.11 or newer, `uv`, `ruff` for lint and format, `mypy`, `pytest`.

```bash
just check        # lint, format, types, tests, coverage floor. Exactly what CI runs.
just test-fast    # the suite with no coverage instrumentation
just coverage     # per-file coverage, worst first, to pick the next test
just fix          # every fix ruff can make on its own, then format
just smoke        # run the packaged script with no project environment
just audit <file> # drive the real entry point
```

## Rules

1. **Clean tree before every commit.** `just check` must pass. Never silence a
   check to go green: no `# type: ignore`, no `# noqa`, no lowering the coverage
   floor. A red check is an unfinished task. If a rule's suggestion genuinely
   makes the code worse, disable it in `pyproject.toml` with the reason written
   down, as `SIM108` is.

2. **Nothing is excluded from the gates.** `engine/` arrived from a tree that was
   excluded from lint and types, and bringing it under them found two real bugs.
   Do not add an exclusion. `production/` is the one exception and it is leaving.

3. **Tests come before the code.** Write the failing test, then implement. For a
   bug, reproduce it first: a fix with no captured repro silently regresses. Never
   weaken a test to get green; if it encodes outdated behaviour, fix or delete it
   and say why in the commit.

4. **The suite is deterministic.** No network, no model call, no clock
   dependence. `tests/conftest.py` enforces this: it clears `OPENAI_API_KEY` and
   blocks `socket.gethostbyaddr`, both autouse. Use the `dns` fixture for DNS and
   `ptr` for a reverse lookup. A test that reaches the network is a test that
   fails for reasons the code did not cause.

5. **Verify against the real surface, not the exit code.** Run the actual command
   on an actual file and read the output. Several defects here were found only by
   doing that: a CLI that rejected `--pretty` after the subcommand, a draft
   scoring NO_GO on eight findings nobody could act on, a check calling a correct
   Ed25519 key weak. Paste the observed output into the commit message.

6. **Tune anything automated against its real output.** The scorer, the LLM
   checks, the DMARC advice. Pull real inputs, read what came out, and ask whether
   you agree with it. Never claim something improved without a before and after.

7. **Stored data stays readable.** `.sendable/` holds a user's history. A record
   written by an older version must still load. Add a field rather than changing
   what one means, and bump `SCHEMA_VERSION` only for a change an older reader
   cannot handle. The store validates on read: a bad field is treated as absent,
   never raised on, because one hand-edited file must not blind every later audit.

8. **Say first before changing how a check reads data.** The audit scorer, the
   DMARC classification chain, and the drift family all reinterpret a user's
   stored history if their judgement shifts. A false finding is the exception:
   fix it, and say clearly in the commit that the interpretation moved.

9. **Design from the caller's side.** Write the call site first and judge it.
   Error messages are part of the interface: a failure a user can hit says what
   went wrong **and** what to do about it. `dmarc.py status` with no reports tells
   you the ingest command to run.

10. **Build for now.** No speculative generality, no unused hooks, no abstraction
    for a single caller. Delete the dead path and migrate every caller in the same
    change. The cleanest codebase is the one with the least code.

11. **Imports at module scope.** No lazy import for convenience, and never catch
    `ImportError` to fall back silently. The exception is a genuinely optional
    dependency, such as `openai`, where the skip path is documented behaviour.

12. **Public copy follows the brand.** The name is **Sendable**. No dashes in
    anything a user reads: use a comma, a colon, or a period. Frame every finding
    in the composer the user is looking at, the subject line, the preview-text
    field, the link URL. Never an HTML tag, a CSS property, or an RFC number.

13. **Each script carries its own dependencies.** `scripts/*.py` have a PEP 723
    header so a user needs only `uv`. Add a dependency to both that header and
    `pyproject.toml`, or the packaged path breaks while the dev path passes. The
    `packaged-script` CI job exists to catch exactly that.

14. **Conventional Commits, and say what you verified.** The commit message is
    where the reasoning lives: what changed, why, what proves it, and what you got
    wrong on the way. Correct an earlier commit's claim in the next one rather
    than amending.
