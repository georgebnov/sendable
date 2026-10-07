"""Social-proof / trust-signal presence (LLM-backed).

David's rule: trust is earned through the body, not front-loaded.
Specific numbers, studies, named results, testimonials, verifiable
statistics — those are the credibility currency. Assertion without
support reads as marketing claim.

One gpt-4o-mini structured-output call (YES/NO). YES → INFO PASS. NO →
LOW advisory. Same defensive-skip pattern as the other LLM checks.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from ..llm import call_structured
from ..parse import ParsedEmail
from ..report import Finding
from ..severity import Severity
from .extract import extract_structured

_MODEL = "gpt-4o-mini"
_BODY_WORD_BUDGET = 400


class _Verdict(BaseModel):
    has_trust_signal: bool = Field(
        description=(
            "True when the body contains at least one specific number, "
            "statistic, data reference, named result, or testimonial. "
            "Generic claims without specifics do not count."
        ),
    )
    reason: str = Field(description="One short sentence — what signal, or that none was found.")
    suggestions: list[str] = Field(
        default_factory=list,
        description=(
            "When has_trust_signal=false, exactly 3 candidate trust-signal "
            "insertions the marketer could add — each one names the kind "
            "of evidence (specific number, named result, testimonial, "
            "data source) and where in the body it would land. Use "
            "placeholders like '[X%]' or '[client name]' where the "
            "marketer needs to fill in real numbers. Empty list when "
            "has_trust_signal=true."
        ),
    )


def _skip(message: str, **details) -> list[Finding]:
    return [
        Finding(
            check="copywriting.social_proof_presence",
            severity=Severity.INFO,
            passed=True,
            message=message,
            details={"skipped": True, **details},
        )
    ]


async def run(email: ParsedEmail) -> list[Finding]:
    structured = extract_structured(email)
    body = "\n\n".join(structured.body_blocks).strip()
    if structured.ps:
        body = (body + "\n\n" + structured.ps).strip()

    if not body:
        return _skip("No body content to inspect for trust signals.")

    excerpt = " ".join(body.split()[:_BODY_WORD_BUDGET])

    verdict = await call_structured(
        check="copywriting.social_proof_presence",
        model=_MODEL,
        system=(
            "You judge whether an email body contains at least one "
            "trust signal: a specific number, a study or data "
            "reference, a named result, a testimonial quote or "
            "attribution, or a verifiable statistic. Generic "
            "marketing claims without specifics do not count. "
            "Give a one-sentence reason. "
            "If has_trust_signal=false, return exactly 3 candidate "
            "trust-signal insertions — each names the kind of "
            "evidence and where it would land, using "
            "placeholders like '[X%]' or '[client name]' for "
            "the real values the marketer fills in. Empty list "
            "when has_trust_signal=true. "
            "IMPORTANT: Specific product model numbers, dated "
            "events, dollar figures, addresses, named locations, "
            "or named results all qualify as trust signals. When "
            "the body already cites concrete specifics, you MUST "
            "return has_trust_signal=true with empty suggestions."
        ),
        user=f"Body:\n{excerpt}",
        response_format=_Verdict,
    )
    if verdict is None:
        return _skip("LLM trust-signal check skipped or failed.")

    if verdict.has_trust_signal:
        return [
            Finding(
                check="copywriting.social_proof_presence",
                severity=Severity.INFO,
                passed=True,
                message=f"Trust signal present. {verdict.reason}",
                details={"reason": verdict.reason},
            )
        ]

    return [
        Finding(
            check="copywriting.social_proof_presence",
            severity=Severity.LOW,
            passed=False,
            message=(
                f"No trust signal detected — email relies entirely on "
                f"assertion with no supporting data or social proof. "
                f"{verdict.reason} Add one specific number, named result, "
                f"or testimonial to earn the claim."
            ),
            details={
                "reason": verdict.reason,
                "suggestions": verdict.suggestions,
            },
        )
    ]
