# Project subagents

Subagents are specialized agents Claude Code can dispatch for a scoped task
(exploring, reviewing, migrating). These are **shared** — committed to git so
everyone gets the same ones.

## Layout

One Markdown file per agent:

```
.claude/agents/<agent-name>.md
```

Frontmatter defines it, followed by the agent's system prompt:

```markdown
---
name: migration-reviewer
description: Reviews an alembic migration for autogenerate noise and destructive ops. Use before committing a migration.
tools: Read, Grep, Glob, Bash
---

You review alembic migrations. Flag any op not related to the intended change
(index renames, AutoString<->TEXT churn), and any destructive DDL...
```

- **`name`** — the agent type you dispatch.
- **`description`** — states *when* to use it; the dispatcher matches on this.
- **`tools`** — optional comma-separated allowlist; omit to inherit all tools.

Keep agents narrow and read-mostly unless they genuinely need to write. See
`AGENTS.md` for repo conventions the agent should respect.
```
