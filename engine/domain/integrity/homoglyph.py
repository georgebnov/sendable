"""Homoglyph scan over subject, visible body text, and link hostnames.

confusable_homoglyphs.is_confusable returns False when clean, else a list of
dicts describing the offending char and its ASCII confusables. A homoglyph
in a link hostname is CRITICAL (classic phishing pattern); elsewhere HIGH.
"""

from __future__ import annotations

from bs4 import BeautifulSoup
from confusable_homoglyphs import confusables

from ...parse import ParsedEmail
from ...report import Finding
from ...severity import Severity


def _plural_clause(n: int) -> str:
    """The count and its clause, agreeing in number."""
    if n == 1:
        return "1 character that looks like a Latin letter but is not one"
    return f"{n} characters that look like Latin letters but are not"


async def run(email: ParsedEmail) -> list[Finding]:
    samples: list[tuple[str, str]] = []
    if email.subject:
        samples.append(("subject", email.subject))
    if email.html:
        soup = BeautifulSoup(email.html, "html.parser")
        body_text = soup.get_text(separator=" ", strip=True)
        if body_text:
            samples.append(("body", body_text))
        for a in soup.find_all("a", href=True):
            samples.append(("link_href", a["href"]))

    hits: list[dict] = []
    for where, text in samples:
        result = confusables.is_confusable(text, preferred_aliases=["latin"])
        if not result:
            continue
        for entry in result:
            char = entry.get("character")
            alias = entry.get("alias")
            if alias in ("LATIN", "COMMON"):
                continue
            # Capture the source text (truncated) so the renderer can show
            # which link / subject / passage contained the bad character.
            source = (text or "")[:200]
            hits.append({"where": where, "char": char, "alias": alias, "source": source})

    if hits:
        severity = (
            Severity.CRITICAL if any(h["where"] == "link_href" for h in hits) else Severity.HIGH
        )
        return [
            Finding(
                check="content.homoglyphs",
                severity=severity,
                passed=False,
                message=(
                    f"The message holds {_plural_clause(len(hits))}. "
                    "Scammers use these to fake a "
                    "brand name. If you did not do it on purpose, retype the "
                    "affected words."
                ),
                details={"hits": hits[:20]},
            )
        ]
    return [
        Finding(
            check="content.homoglyphs",
            severity=Severity.INFO,
            passed=True,
            message="No homoglyphs detected.",
        )
    ]
