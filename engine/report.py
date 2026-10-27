"""The audit Report and the Finding rows it holds.

A Finding is one check's verdict. A Report is every finding plus the composite
score, the verdict, and the per-category sub-scores the scorer derived from them.
Both are pydantic models, so `report.model_dump(mode="json")` is the wire format
every entry point prints.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from .severity import Severity


class Finding(BaseModel):
    check: str
    severity: Severity
    passed: bool
    message: str
    details: dict = Field(default_factory=dict)
    # ─── Scoring metadata (added in scoring rewrite) ────────────────
    # `category` — one of "authentication", "infrastructure", "content",
    # "domain_records", "engagement". Auto-derived from `check` prefix
    # in audit.scoring; explicit override lets a check opt out.
    category: str | None = None
    # `family` — when multiple findings should collapse to a single
    # deduction (e.g. multiple MX-shape findings across MX hosts).
    # Findings sharing a family contribute only their highest severity.
    family: str | None = None
    # `hard_gate` — failing this finding short-circuits to NO_GO with
    # score floored at 30. CRITICAL severity implies hard_gate=True
    # automatically; this lets non-CRITICAL findings opt in too.
    hard_gate: bool = False
    # `source` — who is responsible for this finding. "user_content" =
    # the marketer's editable text/HTML; "esp_template" = chrome the
    # sending tool injects (preview-text span, footer zero-widths);
    # "domain_config" = DNS / auth records the user's domain admin owns.
    # Drives report grouping ("what you can fix" vs "what your tool
    # injects") and lets the scorer down-weight non-user findings.
    source: str = "user_content"


class ModeInfo(BaseModel):
    """How the audit decided whether this is a test send or production
    send, and what cleanup was applied before scoring.

    `label` = TEST | PRODUCTION. `signals` = which heuristics fired
    (e.g. `header:x-mailchimp-test`, `subject:test_prefix`). `cleanup_*`
    fields list the test markers stripped or substituted before scoring
    so the user sees exactly how their test was projected to production.
    """

    label: str = "PRODUCTION"
    signals: list[str] = Field(default_factory=list)
    cleanup_subject_prefix_stripped: str | None = None
    cleanup_headers_stripped: list[str] = Field(default_factory=list)
    cleanup_placeholders_substituted: list[dict] = Field(default_factory=list)


class Report(BaseModel):
    score: int
    verdict: str  # GO | REVIEW | NO_GO
    findings: list[Finding]
    from_addr: str | None = None
    subject: str | None = None
    # ─── Scoring breakdown (populated by audit.scoring) ─────────────
    # Per-category sub-scores 0-100 (skipped categories omitted).
    # Top-level `score` is geometric mean of these weighted by category.
    sub_scores: dict[str, int] = Field(default_factory=dict)
    hard_gates_failed: list[str] = Field(default_factory=list)
    soft_multipliers_applied: list[str] = Field(default_factory=list)
    # ─── Test-vs-production framing ─────────────────────────────────
    # Default = PRODUCTION (no signals, no cleanup) so existing call
    # sites that don't pass mode info still produce valid Reports.
    mode: ModeInfo = Field(default_factory=ModeInfo)
