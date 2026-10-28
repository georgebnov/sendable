# Contributing

Thanks for looking. This is a small, focused tool, and the bar for a change is
that it makes an email audit more accurate or more actionable.

## Setup

You need [`uv`](https://docs.astral.sh/uv/). Nothing else.

```bash
git clone https://github.com/georgebnov/sendable.git && cd sendable
uv sync                      # the development environment
just check                   # lint, types, tests, coverage floor
```

If you do not have [`just`](https://github.com/casey/just), read the `justfile`:
every recipe is two or three plain commands.

Install the commit hook once, so the gate runs before you commit:

```bash
uv tool install pre-commit && pre-commit install
# or, with no extra tool:
git config core.hooksPath .githooks
```

Both run the same checks. Use one, not both.

## The gate

`just check` is the whole gate, and CI runs exactly the same thing on Python 3.11
and 3.14. A green local run means a green CI run.

```
ruff check .            lint
ruff format --check .   formatting
mypy                    types, over engine, store, scripts, and tests
pytest --cov            the suite, with a coverage floor
```

Nothing is excluded from any of them. Do not add an exclusion, and do not silence
a check to go green: no `# type: ignore`, no `# noqa`, no lowering the floor. If a
rule's suggestion genuinely makes the code worse, disable the rule in
`pyproject.toml` with the reason written down. `SIM108` is disabled that way, and
the comment explains why.

## Tests

Write the failing test first, then the code. For a bug, reproduce it before fixing
it: a fix with no captured repro quietly regresses later.

The suite is deterministic by construction, and must stay that way. It makes no
network call and depends on no clock. `tests/conftest.py` enforces this with an
autouse fixture that blocks `socket.gethostbyaddr`. When your check needs DNS, use the `dns` fixture, which
holds a zone in a dict; any name you do not register answers NXDOMAIN, as a real
resolver does. For a reverse lookup, use `ptr`.

A test that reaches the network is a test that fails for reasons the code did not
cause, and it will be rejected.

## Adding a check

A check is one module with one function. It takes what it needs and returns a list
of `Finding`. It owns no state and reaches no database.

```python
async def run(email: ParsedEmail) -> list[Finding]:
    return [
        Finding(
            check="content.my_check",
            severity=Severity.MEDIUM,
            passed=False,
            message="Delete the hidden line of white text above your headline.",
            details={"hits": 1},
        )
    ]
```

Register it in the relevant list in `engine/runner.py`, or in
`engine/domain/runner.py` for a check that reads DNS.

Three things make the difference between a check that helps and one that annoys:

**It must never fire on correct configuration.** A false finding sends someone to
change something that works, which is worse than saying nothing. Two of the bugs
fixed in this repo's first release were exactly that.

**The message is the product.** Write it for the person looking at their email
composer: the subject line, the preview-text field, the link they pasted, the From
name. Never an HTML tag, a CSS property, or an RFC number. "Delete the hidden line
of white text above your headline" is useful. "Your `display:none` div trips
Gmail's salting heuristic" is not.

**No dashes in anything a user reads.** Use a comma, a colon, or a period.

Ship it with tests covering the happy path and at least one failure, and add a
one-line entry to `CHANGELOG.md` under `Unreleased`.

## Changing how an existing check reads data

Say so first, in the issue or the pull request, before the code.

`.sendable/` holds a real user's history. The audit scorer, the DMARC
classification chain, and the drift family all reinterpret that history if their
judgement shifts, which silently changes what every earlier audit meant. Fixing a
false finding is the exception: do it, and say clearly that the interpretation
moved.

A record written by an older version must still load. Add a field rather than
changing what one means.

## Dependencies

A dependency goes in two places: `pyproject.toml`, and the PEP 723 header of every
script that needs it. Miss the header and `just check` still passes while
`uv run scripts/audit.py` fails for a user. A test and a CI job both check for
exactly that mismatch.

Keep the list short. Every dependency is something a user downloads to audit one
email.

## Pull requests

- One concern per pull request.
- Conventional Commits: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `ci:`,
  `build:`, `style:`, `perf:`, `chore:`.
- Run the real command on a real file and paste the output. Several defects here
  were found only by doing that, and never by reading the code.
- Say what you got wrong on the way. It is more useful than a clean story.

## Reporting a problem

An audit report is the most useful thing you can attach, and it may contain a real
subject line, real link URLs, and your sending domain. Redact before you post, or
reproduce with a fixture from `tests/fixtures/`.

For anything that looks like a security issue, read [SECURITY.md](SECURITY.md)
instead of opening an issue.
