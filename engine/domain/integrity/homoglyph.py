"""Homoglyph scan over subject, visible body text, and link hostnames.

A homoglyph attack writes a familiar word with letters from another alphabet
that look the same, so `paypal` with a Cyrillic a reads correctly to a person
and resolves elsewhere for a machine. In a link hostname that is phishing, so
it is CRITICAL; in ordinary text it is HIGH.

The hard part is not spotting non-Latin letters. It is not shouting at an
email written in another language. A Russian newsletter is full of Cyrillic and
impersonates nothing, so the rule is about contrast: a letter counts only when
it is **not Latin**, **looks Latin**, and sits in text that is **otherwise
Latin**. A link is always checked, because a hostname is Latin by convention
whatever language the message is written in.
"""

from __future__ import annotations

import unicodedata

from bs4 import BeautifulSoup

from ...parse import ParsedEmail
from ...report import Finding
from ...severity import Severity

# Non-Latin letters that read as a Latin letter. Kept explicit and short on
# purpose: this is the set that turns up in real phishing, and a reader can
# check every row. A full Unicode confusables table would add thousands of
# pairs nobody has ever been attacked with, and it is what made an ordinary
# Russian newsletter look like an attack.
_LATIN_LOOKALIKE: dict[str, str] = {
    # Cyrillic
    "\u0430": "a",
    "\u0435": "e",
    "\u043e": "o",
    "\u0440": "p",
    "\u0441": "c",
    "\u0445": "x",
    "\u0443": "y",
    "\u0456": "i",
    "\u0458": "j",
    "\u04bb": "h",
    "\u0455": "s",
    "\u0501": "d",
    "\u051b": "q",
    "\u0461": "w",
    "\u043c": "m",
    "\u043d": "h",
    "\u0433": "r",
    "\u0410": "A",
    "\u0412": "B",
    "\u0415": "E",
    "\u041a": "K",
    "\u041c": "M",
    "\u041d": "H",
    "\u041e": "O",
    "\u0420": "P",
    "\u0421": "C",
    "\u0422": "T",
    "\u0425": "X",
    "\u0423": "Y",
    "\u0406": "I",
    # Greek
    "\u03bf": "o",
    "\u03b1": "a",
    "\u03c1": "p",
    "\u03bd": "v",
    "\u03c5": "u",
    "\u03b9": "i",
    "\u03ba": "k",
    "\u03c7": "x",
    "\u03b3": "y",
    "\u03c4": "t",
    "\u0391": "A",
    "\u0392": "B",
    "\u0395": "E",
    "\u0396": "Z",
    "\u0397": "H",
    "\u0399": "I",
    "\u039a": "K",
    "\u039c": "M",
    "\u039d": "N",
    "\u039f": "O",
    "\u03a1": "P",
    "\u03a4": "T",
    "\u03a5": "Y",
    "\u03a7": "X",
    # Armenian and Cherokee, the other two that reach real inboxes
    "\u0585": "o",
    "\u0581": "g",
    "\u13a0": "D",
    "\u13de": "L",
    "\u13df": "C",
}


def _script_of(char: str) -> str:
    """The alphabet a character belongs to.

    A Unicode character name starts with its script, so CYRILLIC SMALL LETTER A
    gives CYRILLIC. Nothing in the standard library exposes the script property
    directly, and the name is stable enough to read it from.
    """
    try:
        return unicodedata.name(char).split()[0]
    except ValueError:
        return "UNKNOWN"


def _dominant_script(text: str) -> str:
    """The alphabet most of the letters belong to. Latin when there are none."""
    counts: dict[str, int] = {}
    for char in text:
        if char.isalpha():
            script = _script_of(char)
            counts[script] = counts.get(script, 0) + 1
    return max(counts, key=lambda k: counts[k]) if counts else "LATIN"


def _lookalikes(text: str) -> list[tuple[str, str]]:
    """Every non-Latin letter in the text that reads as a Latin one."""
    return [
        (char, _script_of(char))
        for char in text
        if char in _LATIN_LOOKALIKE and _script_of(char) != "LATIN"
    ]


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

    # The language the message is written in. A link is judged without it,
    # because a hostname is Latin by convention in any language.
    prose = " ".join(text for where, text in samples if where != "link_href")
    prose_is_latin = _dominant_script(prose) == "LATIN"

    hits: list[dict] = []
    for where, text in samples:
        if where != "link_href" and not prose_is_latin:
            continue
        for char, script in _lookalikes(text):
            # Keep the source text, truncated, so a reader can see which link,
            # subject or passage carried the character.
            hits.append(
                {"where": where, "char": char, "alias": script, "source": (text or "")[:200]}
            )

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
