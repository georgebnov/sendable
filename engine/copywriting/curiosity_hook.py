"""Curiosity-hook check (LLM-backed).

David's rule: the opening must create an open loop — a surprising
stat, a question the reader can't answer yet, or a half-told story.
Closed statements ("Here is our March update") give the reader
permission to stop reading at the subject.

One gpt-4o-mini structured-output call. Input: subject + first 100
words of body. Output: OPEN_LOOP / CLOSED_STATEMENT. LOW advisory on
closed-statement; INFO on open-loop.

Defensive skip pattern shared with `subject_body_mismatch` — any LLM
failure returns INFO PASS so the audit never depends on LLM
availability.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from ..llm import call_structured
from ..parse import ParsedEmail
from ..report import Finding
from ..severity import Severity
from .extract import extract_structured

_MODEL = "gpt-4o-mini"
_OPENING_WORD_BUDGET = 100


class _Verdict(BaseModel):
    classification: Literal["OPEN_LOOP", "CLOSED_STATEMENT"] = Field(
        description=(
            "OPEN_LOOP when the opening creates unresolved tension that the "
            "reader must read further to resolve; CLOSED_STATEMENT when the "
            "opening is a complete factual statement with no forward pull."
        ),
    )
    reason: str = Field(description="One short sentence justifying the call.")
    suggestions: list[str] = Field(
        default_factory=list,
        description=(
            "When classification=CLOSED_STATEMENT, exactly 3 alternative "
            "opening lines that create an open loop, surprising stat, or "
            "unanswerable question. Each ≤2 sentences. Empty list when "
            "classification=OPEN_LOOP."
        ),
    )


def _skip(message: str, **details) -> list[Finding]:
    return [
        Finding(
            check="copywriting.curiosity_hook",
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

    if not body_text:
        return _skip("No body content to inspect for opening hook.")

    opening = " ".join(body_text.split()[:_OPENING_WORD_BUDGET])

    verdict = await call_structured(
        check="copywriting.curiosity_hook",
        model=_MODEL,
        system=(
            "You judge whether an email opening creates a curiosity "
            "gap — an open loop, a surprising statistic, or a "
            "question the reader cannot answer without reading on. "
            "Return classification=OPEN_LOOP when the opening pulls "
            "the reader forward, CLOSED_STATEMENT when it is a "
            "complete factual statement that resolves itself. Give "
            "a one-sentence reason. "
            "If classification=CLOSED_STATEMENT, return exactly 3 "
            "alternative opening lines (each ≤2 sentences) that "
            "create an open loop, surprising stat, or unanswerable "
            "question, grounded in the body's topic. Empty list "
            "when classification=OPEN_LOOP. "
            "IMPORTANT: Many well-written emails open with a real "
            "curiosity gap. If the opening genuinely pulls the reader "
            "forward, you MUST return OPEN_LOOP with empty "
            "suggestions. Do NOT fabricate a problem to justify a "
            "more elaborate response."
        ),
        user=(
            f"Subject: {subject or '(none)'}\n\n"
            f"Opening (first {_OPENING_WORD_BUDGET} words of body):\n"
            f"{opening}"
        ),
        response_format=_Verdict,
    )
    if verdict is None:
        return _skip("LLM hook check skipped or failed.")

    if verdict.classification == "OPEN_LOOP":
        return [
            Finding(
                check="copywriting.curiosity_hook",
                severity=Severity.INFO,
                passed=True,
                message=f"Opening creates a curiosity gap. {verdict.reason}",
                details={"classification": "OPEN_LOOP", "reason": verdict.reason},
            )
        ]

    return [
        Finding(
            check="copywriting.curiosity_hook",
            severity=Severity.LOW,
            passed=False,
            message=(
                f"Opening is a closed statement — reader has permission to "
                f"stop after the first line. {verdict.reason} Lead with an "
                f"open loop, a surprising data point, or a question."
            ),
            details={
                "classification": "CLOSED_STATEMENT",
                "reason": verdict.reason,
                "suggestions": verdict.suggestions,
            },
        )
    ]
