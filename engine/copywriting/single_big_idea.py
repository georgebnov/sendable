"""Single-big-idea check (LLM-backed).

David's rule: one big idea, let it breathe. Two competing ideas dilute
both; three or more turn the email into a digest the reader skims.

One gpt-4o-mini structured-output call. Verdict is exactly one of
"1" / "2" / "3+" distinct central ideas. Bands map to severity:
  • 1   → INFO PASS
  • 2   → MEDIUM (competing ideas, one subordinate)
  • 3+  → HIGH (scattershot)

Defensive skip pattern shared with the other LLM-backed checks — any
LLM failure returns INFO PASS so the audit never blocks on LLM
availability.
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
    idea_count: Literal["1", "2", "3+"] = Field(
        description=(
            "Number of distinct value propositions / central ideas the body "
            "communicates. '1' = single dominant idea. '2' = two ideas, one "
            "clearly subordinate. '3+' = three or more competing ideas."
        ),
    )
    reason: str = Field(description="One short sentence justifying the count.")
    suggestions: list[str] = Field(
        default_factory=list,
        description=(
            "When idea_count is '2' or '3+', exactly 3 candidate single-"
            "idea framings the marketer could choose between — each one "
            "names the central idea to keep, the ideas to cut, and one "
            "sentence on the resulting angle. Empty list when idea_count "
            "is '1'."
        ),
    )


def _skip(message: str, **details) -> list[Finding]:
    return [
        Finding(
            check="copywriting.single_big_idea",
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
        return _skip("No body content to inspect for idea count.")

    excerpt = " ".join(body.split()[:_BODY_WORD_BUDGET])

    verdict = await call_structured_majority(
        key=lambda v: v.idea_count,
        check="copywriting.single_big_idea",
        model=_MODEL,
        system=(
            "You count the number of distinct central ideas or value "
            "propositions an email body communicates. One coherent "
            "pitch around a single topic counts as 1, even if it has "
            "supporting points. Two equally-weighted topics counts "
            "as 2. Three or more independent pitches counts as 3+. "
            "Provide a one-sentence reason. "
            "If idea_count is '2' or '3+', return exactly 3 "
            "candidate single-idea framings the marketer could "
            "choose between. Each suggestion names the idea to "
            "keep, the ideas to cut, and gives a one-sentence "
            "angle. Empty list when idea_count is '1'. "
            "IMPORTANT: A focused email with supporting bullets, "
            "headings, or examples is still ONE idea. Do NOT inflate "
            "the count by treating supporting points as separate "
            "value propositions. When the email is genuinely focused, "
            "return idea_count='1' with empty suggestions."
        ),
        user=f"Body:\n{excerpt}",
        response_format=_Verdict,
    )
    if verdict is None:
        return _skip("LLM idea-count check skipped or failed.")

    if verdict.idea_count == "1":
        return [
            Finding(
                check="copywriting.single_big_idea",
                severity=Severity.INFO,
                passed=True,
                message=f"Single dominant idea. {verdict.reason}",
                details={"idea_count": "1", "reason": verdict.reason},
            )
        ]

    if verdict.idea_count == "2":
        return [
            Finding(
                check="copywriting.single_big_idea",
                severity=Severity.MEDIUM,
                passed=False,
                message=(
                    f"Two competing ideas detected. {verdict.reason} "
                    f"Pick one and let it breathe; demote or cut the other."
                ),
                details={
                "idea_count": "2",
                "reason": verdict.reason,
                "suggestions": verdict.suggestions,
            },
            )
        ]

    return [
        Finding(
            check="copywriting.single_big_idea",
            severity=Severity.HIGH,
            passed=False,
            message=(
                f"Three or more competing value propositions. "
                f"{verdict.reason} Multiple ideas dilute each other — "
                f"split into separate sends or pick the one that matters."
            ),
            details={
                "idea_count": "3+",
                "reason": verdict.reason,
                "suggestions": verdict.suggestions,
            },
        )
    ]
