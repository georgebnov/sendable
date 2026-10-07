"""Pydantic schema for the audit Report and humanized layer."""

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


class HumanizedIssue(BaseModel):
    """One failing finding, translated into plain-English problem + action.

    Location data (where the problem is in the email) is NOT the LLM's job —
    it's computed deterministically from the Finding's details by
    audit.humanize.format_location(). The LLM only writes prose.
    """

    check: str = Field(
        description=(
            "The `check` identifier of the Finding this issue corresponds to. "
            "Must match one of the failing findings in the report exactly "
            "(e.g., 'content.hidden_css_salting', 'auth.dmarc')."
        )
    )
    title: str = Field(
        description="Short human name for the issue (max 60 chars). Plain English, no jargon."
    )
    severity: str = Field(
        description="One of CRITICAL, HIGH, MEDIUM, LOW — mirrors the underlying Finding.severity"
    )
    whats_wrong: str = Field(
        description=(
            "1-2 plain-English sentences explaining what was detected and why it matters for inbox "
            "delivery. "
            "NEVER use these terms without defining them in one clause: DMARC, DKIM, SPF, "
            "RFC 8058, "
            "List-Unsubscribe, CSS, salting, homoglyph. If you have to use one, add a short "
            "definition like "
            "'DMARC (a domain-authentication rule that tells receiving mail servers whether to "
            "trust mail from your domain)'. "
            "Write like you're explaining to a marketer who runs their own newsletter, not a "
            "security engineer."
        )
    )
    user_can_fix: str = Field(
        description=(
            "Must be EXACTLY one of these three values: "
            "'yes' — the user can fix it by editing their email content directly (subject, body, "
            "links, etc.). "
            "'workaround' — the user's email sending tool (Kit, HubSpot, Mailchimp, etc.) injects "
            "this automatically. "
            "The user cannot remove it from the editor; they need to restructure their content to "
            "avoid triggering the "
            "injection, OR switch tools, OR accept the minor penalty. "
            "'infrastructure' — this requires a DNS / domain / email-authentication setup change, "
            "not an email-content change."
        )
    )
    what_to_do: str = Field(
        description=(
            "1-2 plain-English sentences with a concrete action matched to `user_can_fix`:"
            " — If 'yes': give the specific edit (e.g., 'delete the word ignore from the hidden "
            "div', 'replace the "
            "   Cyrillic а in the link with Latin a')."
            " — If 'workaround': NAME the tool if you can infer it from the From address or "
            "headers, "
            "explain briefly "
            "   that the tool injects this automatically, and describe the "
            "restructure/workaround AND "
            "the option to "
            "   accept the minor penalty."
            " — If 'infrastructure': describe the DNS / domain change in layman's terms "
            "   (e.g., 'Ask your developer or domain admin to add a DMARC record to the "
            "example.com "
            "DNS settings')."
        )
    )


class HumanizedReport(BaseModel):
    """LLM-generated human-readable layer on top of Report. Returned by
    audit.humanize.humanize() when failures exist and an LLM is reachable.
    Never sets the score/verdict — that's the deterministic layer's job."""

    summary: str = Field(
        description="One-sentence executive summary of what is hurting this email's deliverability"
    )
    issues: list[HumanizedIssue] = Field(
        description="Failing findings translated into plain English, ordered by severity and impact"
    )
