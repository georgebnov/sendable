"""Feature-vs-benefit framing check (LLM-backed).

David's rule: the body runs on excitement, and excitement comes from
the imagined state. Specs are facts; benefits are the state the spec
unlocks. "Quartz countertops" is a feature; "a counter you don't have
to baby" is the benefit.

One gpt-4o-mini structured-output call. Three-way verdict:
  • BENEFIT_FOCUSED → INFO PASS
  • MIXED           → LOW advisory (some features bare, some framed)
  • FEATURE_ONLY    → LOW advisory (no benefit framing at all)

Defensive skip pattern shared with the other LLM-backed checks.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from ..llm import call_structured_majority
from ..parse import ParsedEmail
from ..report import Finding
from ..severity import Severity
from .extract import extract_structured

_MODEL = "gpt-4o-mini"
_BODY_WORD_BUDGET = 400


class _Verdict(BaseModel):
    framing: Literal["FEATURE_ONLY", "BENEFIT_FOCUSED", "MIXED"] = Field(
        description=(
            "FEATURE_ONLY = features stated as bare facts, no reader-side "
            "outcome. BENEFIT_FOCUSED = each feature framed in terms of "
            "what it does for the reader. MIXED = both patterns present."
        ),
    )
    reason: str = Field(description="One short sentence justifying the call.")
    suggestions: list[str] = Field(
        default_factory=list,
        description=(
            "When framing is FEATURE_ONLY or MIXED, exactly 3 rewrites of "
            "the bare-feature sentences as benefit-framed sentences (what "
            "the feature unlocks for the reader). Empty list when framing "
            "is BENEFIT_FOCUSED."
        ),
    )


def _skip(message: str, **details) -> list[Finding]:
    return [
        Finding(
            check="copywriting.benefit_over_feature",
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
        return _skip("No body content to inspect for feature/benefit framing.")

    excerpt = " ".join(body.split()[:_BODY_WORD_BUDGET])

    verdict = await call_structured_majority(
        key=lambda v: v.framing,
        check="copywriting.benefit_over_feature",
        model=_MODEL,
        system=(
            "You judge whether an email describes features purely "
            "as facts (FEATURE_ONLY), explains what features mean "
            "for the reader (BENEFIT_FOCUSED), or is a mix of both "
            "(MIXED). Emails with no features at all should be "
            "treated as BENEFIT_FOCUSED if the body is reader-"
            "oriented. Give a one-sentence reason. "
            "If framing is FEATURE_ONLY or MIXED, return exactly 3 "
            "rewrites of the bare-feature sentences as benefit-"
            "framed sentences: name the feature and what it "
            "unlocks for the reader. Empty list when framing is "
            "BENEFIT_FOCUSED. "
            "IMPORTANT: A short personal note or update may have no "
            "features at all: that's BENEFIT_FOCUSED. A pitch where "
            "every feature already has reader context is also "
            "BENEFIT_FOCUSED. Do NOT downgrade to MIXED unless at "
            "least one feature is genuinely stated as a bare fact."
        ),
        user=f"Body:\n{excerpt}",
        response_format=_Verdict,
    )
    if verdict is None:
        return _skip("LLM framing check skipped or failed.")

    if verdict.framing == "BENEFIT_FOCUSED":
        return [
            Finding(
                check="copywriting.benefit_over_feature",
                severity=Severity.INFO,
                passed=True,
                message=f"Features framed as reader benefits. {verdict.reason}",
                details={"framing": "BENEFIT_FOCUSED", "reason": verdict.reason},
            )
        ]

    if verdict.framing == "MIXED":
        return [
            Finding(
                check="copywriting.benefit_over_feature",
                severity=Severity.LOW,
                passed=False,
                message=(
                    f"Mixed framing: some features have benefit context, "
                    f"others are bare specs. {verdict.reason} Apply the "
                    f"same framing throughout: what does each feature "
                    f"unlock for the reader?"
                ),
                details={
                    "framing": "MIXED",
                    "reason": verdict.reason,
                    "suggestions": verdict.suggestions,
                },
            )
        ]

    return [
        Finding(
            check="copywriting.benefit_over_feature",
            severity=Severity.LOW,
            passed=False,
            message=(
                f"Feature-only listing: features stated as bare facts "
                f"with no reader-side outcome. {verdict.reason} Excitement "
                f"comes from the imagined state, not the specification."
            ),
            details={
                "framing": "FEATURE_ONLY",
                "reason": verdict.reason,
                "suggestions": verdict.suggestions,
            },
        )
    ]
