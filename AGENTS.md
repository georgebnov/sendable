# Agent guide: Sendable

Sendable is an email deliverability audit tool. It ships as a skill that an agent
downloads and runs. It has no service, no account, and no database. `SKILL.md` is
the contract that an agent reads. This file is the contract for work on the code.

## Layout

```
SKILL.md          the contract for agents. Update it when a flag or an output changes.
scripts/          the two entry points. Each script declares its own dependencies.
  audit.py          grades one email
  dmarc.py          reads aggregate reports and reports the next step
engine/           every check. No database, no network state, and no globals that it owns.
tests/            the suite. No network and no database.
references/       what an agent loads on demand. CONNECTIONS.md (the data sources
                  a sender can connect), PLAYBOOKS.md (the questions one audit
                  cannot answer), CHECKS.md (every check and its thresholds),
                  MECHANISMS.md (how the subtle checks decide).
docs/             maintainer docs. RELEASING.md only.
.claude-plugin/   the plugin manifests, so Claude Code installs the skill in one
                  command. plugin.json points `skills` at the repository root,
                  because the root is the skill. marketplace.json lets a user
                  add this repository as a marketplace.
```

## Toolchain

Python 3.11 or newer, `uv`, `ruff` for lint and format, `mypy`, and `pytest`.

```bash
just check        # lint, format, types, tests, and the coverage floor. CI runs the same.
just test-fast    # the suite without coverage measurement
just coverage     # coverage for each file, worst first, to select the next test
just fix          # every fix that ruff can make alone, then format
just smoke        # run the packaged script without the project environment
just audit <file> # run the real entry point
```

## Rules

These are every rule for working on this code. Some numbers are short, because
the rule they held moved into the maintainer's own global rules, and the number
stays so that code comments and pull requests keep citing the same one.

1. **Keep the tree clean before each commit.** `just check` must pass. The
   Fix forward: never silence a check to make the run green. In this repo, do
   not add `# type: ignore` or `# noqa`, and do not lower the coverage floor. If the
   suggestion of a lint rule makes the code worse, disable the rule in
   `pyproject.toml` and write the reason there. `SIM108` is the example.

2. **Nothing is excluded from the gates.** `engine/` came from a tree that lint
   and the type check excluded. When the gates covered it, they found two real
   bugs. Do not add an exclusion. There is no exception, and there is nothing in
   this repository that is not the skill.

3. **Tests come first, and you never weaken one.** Watch a new test fail before
   you write the code. For a bug, write the failing test first. If a test has to
   change because a decision changed, say why in the commit.

4. **The suite is deterministic.** It has no network and no dependency on the
   clock. `tests/conftest.py` enforces this with an autouse fixture that blocks
   `socket.gethostbyaddr`. Use the `dns` fixture for DNS and the `ptr` fixture
   for a reverse lookup. A test that uses the network fails for reasons that the
   code did not cause.

5. **Run the real command on a real file.** A passing unit test is not enough.
   In this repo, only a real run found these defects:
   - The CLI refused `--pretty` after the subcommand.
   - A draft got NO_GO because of eight findings that nobody could act on.
   - A check called a correct Ed25519 key weak.

   Paste the output that you saw into the commit message.

6. **Tune each automated part against its real output.** Read a sample of real
   inputs and outputs before you call a part improved, and keep the before and
   after. In this repo the automated parts are the scorer and the DMARC
   advice.

7. **Write nothing to the user's disk.** Both entry points read their input and
   print their output. There is no store, no cache, and no state between runs,
   so the same input always gives the same answer. A feature that needs history
   needs the user to pass it in, the way `dmarc.py` takes older reports as its
   baseline.

8. **Say so first, before you change how a check reads data.** The audit scorer
   and the DMARC classification chain decide what a user acts on, so a change to
   either re-grades mail that was already graded. A false finding is the
   exception. Fix it, and say clearly in the commit that the interpretation
   changed.

9. **Design from the side of the caller.** Write the call site first, and judge
   it. Error messages are part of the interface. A failure that a user can see
   says what went wrong **and** what to do next. Example: `dmarc.py` given a file
   that is not a report names the three formats a provider sends, and says to
   check you passed the attachment rather than the message that carried it.

10. **Build for now.** Do not add speculative general code, unused hooks, or an
    abstraction for a single caller. The best codebase has the least code. When
    you replace a code path, delete the old one. Keep a shim only for a named
    contract: a public API, a CLI, a config or data format, or a state seen in
    production. Tests alone are not a contract.

11. **Put imports at module scope.** Do not import lazily for convenience. Never
    catch `ImportError` to fall back silently. There is no exception: every
    dependency this repo declares is required, and each one is imported.

12. **Public text follows the brand.** The name is **Sendable**. Do not use
    dashes in text that a user reads. Use a comma, a colon, or a period. Describe
    each finding in the part of the composer that the user sees: the subject
    line, the preview text field, or the link URL. Never name an HTML tag, a CSS
    property, or an RFC number.

13. **Each script carries its own dependencies.** Each file in `scripts/*.py` has
    a PEP 723 header, so a user needs only `uv`. Add each dependency to that
    header and to `pyproject.toml`. If you add it to only 1 place, the packaged
    path breaks while the development path passes. The `packaged-script` CI job
    finds this error.

14. **Conventional Commits, and do not amend.** `feat|fix|refactor|build|ci|
    chore|docs|style|perf|test`, a lowercase imperative subject of 50 characters
    or fewer, and a body only when the reason is not obvious. Rule 5 holds the
    proof that goes in the commit.
