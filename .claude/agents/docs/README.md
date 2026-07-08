# .claude/agents/docs — working docs

The unclean side of the documentation: drafts, design notes, experiment logs, raw results,
proposals. Committed so it transfers across worktrees and chats; pruned periodically; nothing
outside `.claude/agents/` may depend on it. When something matures, its cleaned product is
promoted to `docs/` and the working copy dies here.

## Suggested layout

- **`reference/`** — system descriptions that can graduate to `docs/` after a freshness pass.
- **`design-decisions/`** — the why behind load-bearing mechanisms: the audit scorer
  (`app/services/audit_service.py` + `app/domain/audit/`), the DMARC classification chain
  (`app/domain/audit/dmarc/`), the iteration fuzzy match (`app/services/iteration_service.py`).
  Internal rationale, not public docs.
- **`research/`** — experiment logs, snapshots, raw results (e.g. tuning the audit scorer or the
  LLM copy against real inputs, per AGENTS.md rule 12).
- **`proposals/`** — specced-but-not-built directions.

Empty for now; add subfolders as working material accumulates. Anything promoted to `docs/`
follows the brand and no-em-dash rules (AGENTS.md rule 15).
