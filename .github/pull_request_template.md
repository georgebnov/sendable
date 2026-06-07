## Summary
<!-- 1-3 sentences. What does this PR do and why. -->

## Data impact
<!-- Tick exactly one. -->

- [ ] **No data impact** — pure code refactor, new feature on net-new fields,
      or change to interpretation of *future* data only. Existing rows
      stay valid as they are. (If checked, also add the `no-data-impact`
      label so CI can pass.)
- [ ] **Changes interpretation of existing data** — something the system
      previously read one way will now be read differently. I've added a
      backfill script under
      `production/backend/app/scripts/backfill/<YYYY_MM_DD>_<name>.py`
      so the change can be re-applied to existing rows post-deploy.

## Test plan
<!-- Bulleted checklist of what you ran / verified. -->
- [ ]
- [ ]
