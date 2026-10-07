"""Audit orchestrator. Fans out checks via asyncio.gather and aggregates.

When `history` is provided, the drift checks run afterward and their
findings are merged into the Report before scoring. Callers that don't
have (or don't want) history simply omit the argument.

`in_spam=True` signals the receiving Gmail mailbox routed the message to
Spam. We surface a HIGH finding and cap the final score at SPAM_SCORE_CAP
so the verdict cannot be GO regardless of how clean the structural checks
look — the recipient already classified the send as spam.

`domain_health=True` (default) runs the mxtoolbox-style sender-domain
audit phase: SPF/DMARC/DKIM record syntax, MTA-STS/TLSRPT/BIMI presence,
top-10 RBL fan-out, and a live SMTP probe of the sender's MX. Each check
is best-effort (timeouts caught, surfaced as INFO findings) so the audit
never fails on transient network issues. Tests pass `domain_health=False`
to keep the smoke suite hermetic.

`force_mode` ('test' | 'production' | None) overrides auto-detection.
Default None = auto-detect. On TEST mode the email is cleaned (subject
prefix stripped, ESP test headers dropped, merge tags substituted with
fake-but-real values) before checks run, so the score reflects what the
production send would look like. Drift checks always see ORIGINAL headers
because drift is about how this real send compares to past real sends.
"""

from __future__ import annotations

import asyncio

from . import llm as _llm
from .cleanup import cleanup
from .copywriting import (
    ai_writing_pattern,
    benefit_over_feature,
    body_composition,
    cta_count,
    cta_outcome_copy,
    curiosity_hook,
    doubt_creation,
    fake_reply_subject,
    from_name_body_consistency,
    generic_opener,
    heuristics,
    link_quality,
    long_paragraph,
    personal_from_name,
    preheader_quality,
    preheader_repeats_subject,
    reading_level,
    single_big_idea,
    social_proof_presence,
    subject,
    subject_body_mismatch,
    subject_deadwords,
    subject_word_count,
    urgency_position,
    voice_consistency,
)
from .domain.auth import alignment, tls_transport
from .domain.auth import results as auth_results
from .domain.integrity import (
    attachments,
    headers,
    hidden_css,
    homoglyph,
    invisible_chars,
    microsoft_eop,
    observability,
    size,
    template_quality,
    unsubscribe,
)
from .forward import calibrate_for_forward, extract_original, is_forwarded
from .free_mailbox import calibrate_for_free_mailbox
from .history import EmailFacts
from .mode import detect as detect_mode
from .parse import ParsedEmail
from .report import Finding, ModeInfo, Report
from .scoring import score_findings
from .severity import Severity

CHECKS = [
    # ─── Domain — auth ────────────────────────────────────────────────
    auth_results.run,
    alignment.run,
    tls_transport.run,
    # ─── Domain — integrity (transport / headers / adversarial) ──────
    size.run,
    headers.run,
    hidden_css.run,
    invisible_chars.run,
    homoglyph.run,
    unsubscribe.run,
    observability.run,
    template_quality.run,
    attachments.run,
    microsoft_eop.run,
    # ─── Copywriting (subject / body / links / heuristics) ───────────
    subject.run,
    subject_word_count.run,
    subject_deadwords.run,
    fake_reply_subject.run,
    subject_body_mismatch.run,
    personal_from_name.run,
    from_name_body_consistency.run,
    preheader_quality.run,
    preheader_repeats_subject.run,
    ai_writing_pattern.run,
    urgency_position.run,
    voice_consistency.run,
    doubt_creation.run,
    long_paragraph.run,
    curiosity_hook.run,
    single_big_idea.run,
    benefit_over_feature.run,
    social_proof_presence.run,
    body_composition.run,
    link_quality.run,
    reading_level.run,
    generic_opener.run,
    cta_count.run,
    cta_outcome_copy.run,
    heuristics.run,
]

# Cap when the receiving mailbox already routed the message to Spam.
# 50 sits below SCORE_REVIEW_MIN (65) so the verdict is forced to NO_GO,
# but stays above 0 so partial structural credit is still visible.
SPAM_SCORE_CAP = 50


async def audit(
    email: ParsedEmail,
    history: list[EmailFacts] | None = None,
    *,
    in_spam: bool = False,
    domain_health: bool = True,
    force_mode: str | None = None,
    probe_unsub: bool = False,
) -> Report:
    # ─── Step 1: detect mode ────────────────────────────────────────
    mode_result = detect_mode(email, force=force_mode)

    # ─── Step 2: cleanup (test → production-shaped) ─────────────────
    if mode_result.is_test:
        cleaned_email, cleanup_report = cleanup(email)
    else:
        cleaned_email, cleanup_report = email, None

    # Forwarded email: grade the original campaign, not the forward chrome.
    # Content is recovered from the forwarded body; the scrambled auth /
    # transport / hidden-char findings are muted after scoring (below).
    forwarded = is_forwarded(email)
    if forwarded:
        cleaned_email = extract_original(cleaned_email)

    mode_info = ModeInfo(
        label=mode_result.label,
        signals=mode_result.signals,
        cleanup_subject_prefix_stripped=(
            cleanup_report.subject_prefix_stripped if cleanup_report else None
        ),
        cleanup_headers_stripped=(cleanup_report.headers_stripped if cleanup_report else []),
        cleanup_placeholders_substituted=(
            cleanup_report.placeholders_substituted if cleanup_report else []
        ),
    )

    # ─── Step 3: per-email checks + drift + domain-health, all in
    # one asyncio.gather. None of them depend on each other so we
    # collapse what used to be three sequential phases into one
    # concurrent fan-out. Wall time is bounded by the slowest single
    # check (LLM tail latency for content; DNS round-trips for
    # domain_health). On a typical send: 3–5s wall instead of 8–20s
    # sequential.
    _llm.reset_accumulator()

    content_tasks = [c(cleaned_email) for c in CHECKS]

    async def _drift_bucket() -> list[Finding]:
        if history is None:
            return []
        from engine.drift.runner import run_drift

        return await run_drift(email, history)

    async def _dh_bucket() -> list[Finding]:
        if not domain_health:
            return []
        from engine.domain.runner import run_domain_health

        return await run_domain_health(cleaned_email)

    async def _unsub_bucket() -> list[Finding]:
        if not probe_unsub:
            return []
        from .domain.integrity import unsubscribe_live

        return await unsubscribe_live.run(cleaned_email)

    all_results = await asyncio.gather(
        *content_tasks,
        _drift_bucket(),
        _dh_bucket(),
        _unsub_bucket(),
    )

    _acc = _llm.get_accumulator()
    if _acc and _acc["calls"]:
        import sys as _sys

        print(
            f"[llm] AUDIT TOTAL calls={_acc['calls']} "
            f"in={_acc['in']} out={_acc['out']} "
            f"cost=${_acc['usd']:.6f}",
            file=_sys.stderr,
        )
    findings: list[Finding] = [f for sub in all_results for f in sub]

    if in_spam:
        findings.append(
            Finding(
                check="delivery.spam_folder",
                severity=Severity.HIGH,
                passed=False,
                message=(
                    "Gmail routed this message to Spam. The recipient mailbox "
                    "has already classified it as spam — score capped at "
                    f"{SPAM_SCORE_CAP}."
                ),
                details={"score_cap": SPAM_SCORE_CAP},
                hard_gate=True,
            )
        )

    # Free-mailbox calibration: a personal-mailbox sender can't authenticate a
    # domain they don't own, so drop the auth / domain-record findings (incl.
    # the hard-gate) and surface one advisory instead — the score then reflects
    # only the categories the sender controls.
    findings = calibrate_for_free_mailbox(findings, cleaned_email.from_addr)
    if forwarded:
        findings = calibrate_for_forward(findings)

    result = score_findings(findings, in_spam=in_spam)
    return Report(
        score=result["score"],
        verdict=result["verdict"],
        findings=findings,
        from_addr=cleaned_email.from_addr,
        subject=cleaned_email.subject,
        sub_scores=result["sub_scores"],
        hard_gates_failed=result["hard_gates_failed"],
        soft_multipliers_applied=result["soft_multipliers_applied"],
        mode=mode_info,
    )
