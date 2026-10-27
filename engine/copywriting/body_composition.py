"""Body-composition sanity: plain-text alternative presence, and image-heavy
ratio detection.

- Having a `text/plain` alternative is itself a legitimacy signal to modern
  filters; missing or empty → MEDIUM.
- Image-only / image-heavy emails with thin visible text are a classic spam
  pattern (Email on Acid empirical: <500 chars visible text + >3 images
  trips four common filters).
"""

from __future__ import annotations

from bs4 import BeautifulSoup

from ..parse import ParsedEmail
from ..report import Finding
from ..severity import Severity

_PLAIN_MIN_CHARS = 100
_VISIBLE_TEXT_FLOOR = 500
_IMAGE_COUNT_CEILING = 3


async def run(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []

    plain = (email.plain_text or "").strip()
    if len(plain) >= _PLAIN_MIN_CHARS:
        findings.append(
            Finding(
                check="content.plain_text_alternative",
                severity=Severity.INFO,
                passed=True,
                message=f"text/plain alternative present ({len(plain)} chars).",
                details={"chars": len(plain)},
            )
        )
    else:
        findings.append(
            Finding(
                check="content.plain_text_alternative",
                severity=Severity.MEDIUM,
                passed=False,
                message=(
                    f"This email has no plain text version, or it holds only "
                    f"{len(plain)} characters. Every real email tool sends one "
                    "beside the designed version, for readers whose client blocks "
                    "images. Filters read a missing one as a sign of bulk mail."
                ),
                details={"chars": len(plain), "min": _PLAIN_MIN_CHARS},
            )
        )

    # Image-to-text ratio check. Only runs when HTML is present.
    if email.html:
        soup = BeautifulSoup(email.html, "lxml")
        # Strip scripts/styles before counting visible text.
        for tag in soup.find_all(["script", "style"]):
            tag.decompose()
        visible_text = soup.get_text(separator=" ", strip=True)
        # Normalize whitespace so padding chars don't inflate the count.
        visible_len = len(" ".join(visible_text.split()))
        image_count = len(soup.find_all("img"))

        if visible_len < _VISIBLE_TEXT_FLOOR and image_count > _IMAGE_COUNT_CEILING:
            findings.append(
                Finding(
                    check="content.image_text_ratio",
                    severity=Severity.HIGH,
                    passed=False,
                    message=(
                        f"Image-heavy layout: {image_count} images with only "
                        f"{visible_len} chars of visible text. Trips multiple "
                        f"spam filters; target ≥{_VISIBLE_TEXT_FLOOR} chars."
                    ),
                    details={
                        "visible_chars": visible_len,
                        "image_count": image_count,
                        "text_floor": _VISIBLE_TEXT_FLOOR,
                    },
                )
            )
        else:
            findings.append(
                Finding(
                    check="content.image_text_ratio",
                    severity=Severity.INFO,
                    passed=True,
                    message=(f"Visible text {visible_len} chars, {image_count} images."),
                    details={"visible_chars": visible_len, "image_count": image_count},
                )
            )

    return findings
