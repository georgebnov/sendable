"""Subject-line deadwords check.

Words that telegraph "low-urgency broadcast" measurably suppress opens.
Zippia open-rate data: subjects containing "newsletter" see −18.7% opens
relative to control; the same pattern extends to the broader broadcast-
content vocabulary (update / digest / roundup / weekly / monthly /
edition / issue).

Existing `copygen.body_newsletter_word` flags "newsletter" in the body
only. This check is the subject-line counterpart with the full set —
distinct scope (subject vs body), distinct vocabulary.

Match: case-insensitive, word-boundary regex against each flag token.
Multi-character word boundaries keep "weekly" from matching inside
unrelated compounds.
"""

from __future__ import annotations

import re

from ..parse import ParsedEmail
from ..report import Finding
from ..severity import Severity

_DEADWORDS = (
    "newsletter",
    "update",
    "digest",
    "roundup",
    "weekly",
    "monthly",
    "edition",
    "issue",
)

_DEADWORD_RX = re.compile(
    r"\b(?:" + "|".join(re.escape(w) for w in _DEADWORDS) + r")\b",
    re.IGNORECASE,
)


async def run(email: ParsedEmail) -> list[Finding]:
    subj = (email.subject or "").strip()
    if not subj:
        return [
            Finding(
                check="copywriting.subject_deadwords",
                severity=Severity.INFO,
                passed=True,
                message="No subject to scan (covered by content.subject_present).",
                details={},
            )
        ]

    # Brand-prefix carve-out: when the subject is shaped like
    # "Brand Series Name: actual subject" — i.e. a short colon-prefixed
    # tag — anything inside that prefix is series naming, not deadword
    # noise (e.g. 'Acme Wave Weekly: ...'). Only flag deadwords that
    # land AFTER the colon. A brand prefix is recognised by being ≤ 4
    # words long. Longer prefixes are unusual and we treat them as the
    # real subject.
    colon = subj.find(":")
    scan_from = 0
    branded_prefix: str | None = None
    if colon != -1:
        prefix = subj[:colon]
        prefix_words = prefix.split()
        rest = subj[colon + 1 :].strip()
        if 0 < len(prefix_words) <= 4 and rest:
            scan_from = colon + 1
            branded_prefix = prefix.strip()

    hits = sorted(
        {m.group(0).lower() for m in _DEADWORD_RX.finditer(subj) if m.start() >= scan_from}
    )

    if hits:
        return [
            Finding(
                check="copywriting.subject_deadwords",
                severity=Severity.MEDIUM,
                passed=False,
                message=(
                    f"Subject contains broadcast-content deadword(s): "
                    f'{", ".join(hits)}. Words like "newsletter" cost '
                    f"about 18.7% of opens (Zippia). Replace with a specific "
                    f"noun or outcome from the body."
                ),
                details={"matches": hits, "subject": subj},
            )
        ]

    msg = "Subject avoids broadcast-content deadwords."
    if branded_prefix is not None:
        # Surface the carve-out for transparency so the user knows we
        # noticed the words but recognised them as series naming.
        msg += (
            f" Treated branded prefix '{branded_prefix}' as series name —"
            " deadwords inside it don't count."
        )
    return [
        Finding(
            check="copywriting.subject_deadwords",
            severity=Severity.INFO,
            passed=True,
            message=msg,
            details={"subject": subj, "branded_prefix": branded_prefix},
        )
    ]
