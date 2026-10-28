## Summary

<!-- What this changes and why, in two or three sentences. -->

## Proof

<!--
Run the real command on a real file and paste the output. Reading the code is not
proof; several defects in this repo were found only by driving the actual surface.

  uv run scripts/audit.py <file> --offline --pretty
  uv run scripts/dmarc.py <report.xml.gz> --domain <domain>

For a changed check, show the before and after on the same input.
-->

```
```

## Checks

- [ ] `just check` passes: ruff, ruff format, mypy, and the suite with the
      coverage floor. Nothing silenced, no exclusion added, the floor not lowered.
- [ ] New behaviour has a test. A bug fix has a test that reproduces the bug first.
- [ ] `CHANGELOG.md` has a one-line entry under `Unreleased`, if this is
      user-visible.

## Does this change how an existing check reads data?

<!-- Tick one. -->

- [ ] **No.** New check, new field, or a change that only affects what a future
      run reports.
- [ ] **Yes.** Something previously read one way is now read differently, so a
      report a user kept from an earlier run no longer agrees with one run today.
      Explain below what moved and why.

<!-- If yes, explain here: -->

## User-facing copy

- [ ] Any new finding message is written for someone looking at their email
      composer: the subject line, the preview-text field, the link URL. No HTML
      tags, no CSS properties, no RFC numbers.
- [ ] No dashes in anything a user reads. Commas, colons, or periods.
- [ ] A new dependency is in **both** `pyproject.toml` and the PEP 723 header of
      every script that needs it.
