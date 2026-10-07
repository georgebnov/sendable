"""Copywriting checks for inbound audits.

Reuses the deterministic rule helpers from `copy_gen/critic.py` — the same
rules that gate outbound generated copy — and applies them to an inbound
ParsedEmail. Findings emitted with `copywriting.*` prefix so they don't
collide with outbound `copygen.*` findings.

Checks run:
 - Subject heuristics (length, word count, Title Case, ALL CAPS, !/?
   counts, Re:/Fwd: prefix, newsletter word, emoji count, $-opener).
 - Spam-trigger substring scan (real-estate compounding vocabulary).
 - Compound-signal score (3+ promotional categories = MEDIUM, 4+ = HIGH,
   5+ = CRITICAL) — the research-backed insight that stacked signals are
   the real deliverability killer.
 - Body word count (judged against a soft 450-word ceiling for inbound
   audits — we don't know the sender's target length).
 - Link count + Google-Drive destination.
 - Emoji count.
 - "newsletter" word in body.

Deliberately skipped: sign-off shape (can't distinguish body from sign-off
in a parsed inbound email). LLM-authored copywriting pointers (storytelling
framework, friction-ack, hook quality) are a separate, future addition.
"""

from __future__ import annotations

from engine.critic import (
    _check_body_emoji,
    _check_body_length,
    _check_body_newsletter_word,
    _check_body_shouting,
    _check_compound_signal,
    _check_links,
    _check_spam_triggers,
    _check_subjects,
    _load_trigger_map,
)

from ..parse import ParsedEmail
from ..report import Finding
from .extract import extract_structured

_OLD_PREFIX = "copygen."
_NEW_PREFIX = "copywriting."


def _relabel(findings: list[Finding]) -> list[Finding]:
    """Rewrite `copygen.*` checks to `copywriting.*` for audit-side reports."""
    out: list[Finding] = []
    for f in findings:
        if f.check.startswith(_OLD_PREFIX):
            new_check = _NEW_PREFIX + f.check[len(_OLD_PREFIX):]
            f = f.model_copy(update={"check": new_check})
        out.append(f)
    return out


def _narrative_body(structured) -> str:
    """Joined narrative for substring/length checks. Excludes greeting,
    footer, signature — those have their own checks and bias word counts.
    Includes P.S. (it's still copywriting surface area)."""
    parts = [*structured.body_blocks]
    if structured.ps:
        parts.append(structured.ps)
    return "\n\n".join(parts)


async def run(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []

    structured = extract_structured(email)
    subject = structured.subject or ""
    # Preview-text used for spam-trigger scan. Prefer real preheader from
    # hidden HTML; fall back to opening body line when no preheader was
    # shipped (substring matching only — not authoritative).
    preview = (
        structured.preview_text
        or (structured.body_blocks[0][:120] if structured.body_blocks else "")
    )
    body = _narrative_body(structured)

    # Subject heuristics — single-variant mode (inbound has one subject).
    findings.extend(_relabel(_check_subjects([subject])))

    # Spam-trigger scan + compound-signal score.
    trigger_map = _load_trigger_map()
    trigger_findings, fired_categories = _check_spam_triggers(
        subject, preview, body, trigger_map,
    )
    findings.extend(_relabel(trigger_findings))
    findings.extend(_relabel(_check_compound_signal(fired_categories)))

    # Body length — use 'long' length hint so the ceiling is 450 words,
    # avoiding false positives on legitimate longer newsletters while still
    # catching truly sprawling messages.
    findings.extend(_relabel(_check_body_length(body, "long")))

    # Links + Drive destination.
    findings.extend(_relabel(_check_links(body)))

    # Body shouting (ALL-CAPS, `!!`, excessive `!`).
    findings.extend(_relabel(_check_body_shouting(body)))

    # Emoji + newsletter word.
    findings.extend(_relabel(_check_body_emoji(subject, body)))
    findings.extend(_relabel(_check_body_newsletter_word(body)))

    # Every individual check now emits a PASS line when its rules don't
    # trigger, so the Technical breakdown lists the full rollcall of
    # copywriting checks that ran against this email.
    return findings
