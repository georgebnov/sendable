# Project skills

Skills are reusable workflows that Claude Code and other agents can run in this
repo. They are committed, so every checkout and every agent gets them.

## Layout

One directory per skill, each holding a `SKILL.md`:

```
.claude/skills/
  ready-for-merge/SKILL.md
```

## ready-for-merge

The gate before any PR merges. It runs a code review with fixes, resolves every
review comment, and audits the diff against `AGENTS.md`.

Do not confuse it with `SKILL.md` at the repo root. That one is the contract for
an agent **using** Sendable. These are for an agent **working on** Sendable.
