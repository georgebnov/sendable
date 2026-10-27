# Releasing

This repository is distributed from Git. There is no package on PyPI and no build
artifact: a user clones it, or downloads a source archive, and runs a script with
`uv`. `pyproject.toml` exists so the project is developable and so the dependency
list has one authoritative home.

That shapes what a release is. It is a tag, a GitHub Release, and a finalized
changelog section. Nothing is published to a registry.

## Steps

1. Confirm the release commit is green. `just check` locally, and the `Skill`
   workflow on the exact head, covering Python 3.11 and 3.14 plus the
   `packaged-script` job. That second job is the one that proves a user with only
   `uv` can run the scripts, so a release never goes out without it.

2. Drive each entry point once, by hand, and read the output. The suite does not
   touch the network and the release should not be the first time anything does.

   ```bash
   uv run scripts/audit.py tests/fixtures/clean_bulk.eml --pretty
   uv run scripts/audit.py tests/fixtures/broken_bulk.eml --offline
   just smoke
   ```

3. Move the accumulated `Unreleased` entries into `## X.Y.Z - YYYY-MM-DD`, keep
   contributor credit, and add a one-line **Highlights** lead-in. Leave an empty
   `## Unreleased` above it. Patch for fixes, minor for a new check or a new flag.

   A new check or a changed threshold is **minor, not patch**, even when it reads
   like a fix. It changes the score a user sees on mail they already audited.

4. Land the release pull request and update a clean `main`.

5. Tag and publish.

   ```bash
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   gh release create vX.Y.Z --verify-tag --notes-file <the changelog section>
   ```

6. Verify, rather than assume. The release is not a draft, its tag resolves to the
   intended commit, and its body matches the changelog section exactly.

   ```bash
   gh release view vX.Y.Z --json isDraft,tagName,targetCommitish,body
   ```

## Version meaning

The version describes what a user sees, not how the code is arranged.

| Change | Bump |
|---|---|
| A new check, or a new flag | minor |
| A changed severity or threshold | minor |
| A changed finding message | patch |
| A fixed false finding | patch |
| A refactor with identical output | none |

A change to how a stored record is read gets its own section in the release notes,
naming what moved, because it changes what every earlier audit in a user's
`.sendable/` meant.
