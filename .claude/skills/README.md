# Project skills

Skills are reusable slash-command workflows available to Claude Code (and other
agents) in this repo. These are **shared** — committed to git so the whole team
and any AFK agents get them. Personal config stays in `settings.local.json`
(gitignored).

## Layout

One directory per skill, each containing a `SKILL.md`:

```
.claude/skills/<skill-name>/SKILL.md
```

`SKILL.md` is YAML frontmatter followed by the instructions the model executes:

```markdown
---
name: deploy-api
description: Deploy the FastAPI service and run pending migrations. Use when shipping backend changes to prod.
---

1. `git checkout main && git pull` (copilot deploys the local tree).
2. `copilot svc deploy --name api --env prod`.
3. Run `alembic upgrade head` in the container.
...
```

- **`name`** — kebab-case; how it's invoked (`/deploy-api`).
- **`description`** — one line stating *when* to use it. This is what the model
  matches on, so make it specific.

Keep each skill focused on one repeatable workflow. Good candidates here: deploy,
run-the-net, new migration, scaffold a backfill script. See `AGENTS.md` at the
repo root for the underlying commands.
```
