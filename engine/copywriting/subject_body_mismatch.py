"""Subject vs body semantic-alignment check (LLM-backed).

CAN-SPAM §5(a)(2): the subject line must accurately reflect the content
of the message. Deterministic rules can catch a few patterns (`Re:`
spoofing, deadword phrasing) but the substantive question — "does the
subject promise X, and does the body deliver X?" — requires reading
both. One gpt-4o-mini structured-output call.

Defensive failure modes (all INFO PASS so the audit never breaks on
LLM availability):
  • `OPENAI_API_KEY` missing → skip with note.
  • `openai` package not importable → skip with note.
  • Any API exception → skip with note (logged to stderr).
  • Either subject or body missing → skip (other checks cover the
    absent-input case).
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from ..llm import call_structured
from ..parse import ParsedEmail
from ..report import Finding
from ..severity import Severity
from .extract import extract_structured

_MODEL = "gpt-4o-mini"
_BODY_WORD_BUDGET = 300

_SYSTEM_PROMPT = (
    "You judge whether an email subject line accurately describes the body "
    "content of the email. CAN-SPAM §5(a)(2) requires that the subject not "
    "mislead about the message's content. Return matches=true if the "
    "subject's promised topic, offer, or question is delivered in the body; "
    "matches=false if the subject implies content that is absent or "
    "unanswered. Provide a one-sentence reason. "
    "If matches=false, return exactly 3 alternative subject lines that "
    "would accurately describe the body content (under 60 chars each, "
    "no clickbait, no Re:/Fwd: prefix). If matches=true, return an empty "
    "list. "
    "IMPORTANT: Many emails are genuinely well-aligned. When the subject "
    "and body match, you MUST return matches=true with empty suggestions. "
    "Do NOT invent a mismatch to justify a more elaborate response: "
    "a clean PASS is the correct verdict for the majority of real emails."
)
_USER_PROMPT = (
    "Subject: {subject}\n\n"
    "Body (first {n} words):\n{body}\n\n"
    "Does the subject accurately describe this body?"
)


class _Verdict(BaseModel):
    matches: bool = Field(description="True when subject and body are topically aligned.")
    reason: str = Field(description="One short sentence explaining the verdict.")
    suggestions: list[str] = Field(
        default_factory=list,
        description=(
            "When matches=false, exactly 3 alternative subject lines that "
            "would accurately describe the body (under 60 chars each, "
            "sentence case, no Re:/Fwd: prefix). Empty list when matches=true."
        ),
    )


def _skip(message: str, **details) -> list[Finding]:
    return [
        Finding(
            check="copywriting.subject_body_mismatch",
            severity=Severity.INFO,
            passed=True,
            message=message,
            details={"skipped": True, **details},
        )
    ]


async def run(email: ParsedEmail) -> list[Finding]:
    structured = extract_structured(email)
    subject = (structured.subject or "").strip()
    body_text = "\n\n".join(structured.body_blocks).strip()
    if structured.ps:
        body_text = (body_text + "\n\n" + structured.ps).strip()

    if not subject or not body_text:
        return _skip(
            "Skipped: need both subject and body to grade alignment.",
            subject_present=bool(subject),
            body_present=bool(body_text),
        )

    words = body_text.split()
    excerpt = " ".join(words[:_BODY_WORD_BUDGET])

    verdict = await call_structured(
        check="copywriting.subject_body_mismatch",
        model=_MODEL,
        system=_SYSTEM_PROMPT,
        user=_USER_PROMPT.format(subject=subject, n=_BODY_WORD_BUDGET, body=excerpt),
        response_format=_Verdict,
    )
    if verdict is None:
        return _skip("LLM alignment check skipped or failed.")

    if verdict.matches:
        return [
            Finding(
                check="copywriting.subject_body_mismatch",
                severity=Severity.INFO,
                passed=True,
                message=f"Subject aligns with body: {verdict.reason}",
                details={
                    "reason": verdict.reason,
                    "subject": subject,
                },
            )
        ]

    return [
        Finding(
            check="copywriting.subject_body_mismatch",
            severity=Severity.HIGH,
            passed=False,
            message=(
                f"Subject does not accurately describe body content: "
                f"CAN-SPAM §5(a)(2) deceptive-subject risk. {verdict.reason}"
            ),
            details={
                "reason": verdict.reason,
                "subject": subject,
                "suggestions": verdict.suggestions,
            },
        )
    ]
