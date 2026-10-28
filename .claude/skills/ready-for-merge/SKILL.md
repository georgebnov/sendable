---
name: ready-for-merge
description: Mandatory pre-merge gate for every PR. Runs /code-review max --fix, resolves every review comment (Greptile, human reviewers), and verifies the diff complies with AGENTS.md. Use whenever the user says a PR is ready to merge, asks to merge, or invokes /ready-for-merge.
---

# Ready for Merge

The **mandatory gate before merging any PR** in this repository. Do not merge, and do not tell
the user a PR is ready to merge, until every step below has completed and passes.

Work against the PR for the current branch (`gh pr view --json number,url,headRefName`). If no
PR exists, stop and tell the user.

## Step 1: Code review with fixes, scaled to the PR

Look at the PR's diff (`gh pr diff <number> --stat` and the diff itself) and pick the
code-review effort level that matches its breadth and risk: don't default to the maximum:

- **low**: mechanical or single-concern changes: a flag flip, a docstring/docs edit, a
  dependency bump, a few-line fix with an obvious test.
- **medium**: a small focused change: one behavior touched across a handful of files, new
  code paths that are well covered by tests. Most small PRs land here.
- **high**: a multi-file feature, changes to shared infrastructure, or anything where a
  subtle interaction with existing callers is plausible.
- **xhigh**: large or risky PRs: core engine/provider seams, data-loss or security surface,
  broad refactors, anything hard to roll back once merged.

State the level you chose and why in one sentence, then run the `code-review` skill with args
`<level> --fix`.

Let it finish and apply its fixes before moving on. If it applied changes, re-run the project
gate afterwards (see Step 3)

## Step 2: Resolve every review comment on the PR

Fetch **all** comments and review threads on the PR: from Cursor (bugbot), Greptile, any other
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
3. If invalid or out of scope: reply to the thread explaining *why*: never silently ignore it.
4. Mark the thread resolved (GraphQL `resolveReviewThread`) once addressed.

The step is done only when zero unresolved review threads remain. Re-check with the GraphQL
query above; do not assume.

## This process is iterative: wait for reviewers to react

Greptile re-reviews on every push and humans may add comments. One pass is never enough. After
each push:

1. Wait ~180s for Greptile to re-run. This harness blocks a foreground `sleep`, so run it
   backgrounded (`sleep 180` via a background shell) or schedule a wakeup, then continue.
2. Re-fetch all comments and review threads (Step 2 queries).
3. If new unresolved comments appeared, handle them as in Step 2, push, repeat from 1.
4. Exit only when a full 3-minute wait produces **zero** new comments and zero unresolved
   threads.

## Step 3: AGENTS.md compliance

Read `AGENTS.md` in full and audit the PR's diff (`gh pr diff <number>`) against every rule.
Key checks for this repo:

- **The gate passes** (rule 1). `just check` runs lint, format, types, the suite, and the
  coverage floor. Never silence a check (`# type: ignore`, `# noqa`) to go green, and never
  lower the floor. If a lint rule makes the code worse, disable it in `pyproject.toml` with
  the reason written there.
- **Nothing new is excluded from the gates** (rule 2). `production/` is the only exception,
  and it is going away.
- **Tests come first.** New behavior ships with a test you watched fail. A bug fix ships with
  a test that failed before the fix. Never delete or weaken a test to go green.
- **The suite stays deterministic** (rule 4). No network, no dependency on the
  clock. Use the `dns` fixture for DNS and the `ptr` fixture for a reverse lookup.
- **The real command ran on a real file** (rule 5). A passing unit test is not enough. Paste
  the output you saw into the commit message.
- **Stored data stays readable** (rule 7). Add a field, never change the meaning of one.
  `SCHEMA_VERSION` moves only for a change an older reader cannot read.
- **Interpretation changes are announced** (rule 8). The scorer, the DMARC classification
  chain, and the drift family re-read a user's stored history. If the judgement changes, the
  commit says so in plain words.
- **Error messages are part of the interface** (rule 9). A failure a user can see says what
  went wrong **and** what to do next.
- **No speculative code** (rule 10). No unused hook, no abstraction for one caller. When a
  code path is replaced, the old one is deleted.
- **Imports at module scope** (rule 11). No `ImportError` fallback, and no
  optional dependency: every declared dependency is required and imported.
- **Public text follows the brand** (rule 12). The name is **Sendable**. No dashes in text a
  user reads. Describe a finding in the part of the composer the user sees, never an HTML tag,
  a CSS property, or an RFC number.
- **Each script carries its dependencies** (rule 13). A new dependency goes in the script's
  PEP 723 header **and** in `pyproject.toml`. The `packaged-script` CI job catches a miss.
- Conventional Commits, no em dashes in the subject or body, no agent attribution.

## Step 4: Report

Push any fixes from Steps 1: 3, then report a checklist:

- [ ] `/code-review max --fix` completed (N findings, M fixed)
- [ ] All review comments resolved (list each commenter and how their comments were handled)
- [ ] AGENTS.md audit clean (note any rules that required fixes)
- [ ] Full project gate green for every stack touched
- [ ] Final 3-minute wait after the last push produced zero new comments

Only after all boxes are checked may the PR be merged. If anything cannot be resolved, report it
as a blocker instead of merging.
