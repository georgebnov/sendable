"""Link-quality checks: URL shorteners and anchor-text vs href domain mismatch.

- Shorteners (bit.ly, t.co, etc.) compound with other SpamAssassin signals;
  cheap win to flag at MEDIUM.
- Anchor-text displaying a domain that differs from the href's registrable
  domain is the classic phishing pattern ("paypal.com" linking to evil.tk).
  Registrable-domain comparison uses a stdlib approximation (not tldextract)
  which handles single-label TLDs perfectly and multi-label TLDs like
  co.uk via a small known-list. ~90% accuracy; flagged in BACKLOG.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..htmltree import parse_html
from ..parse import ParsedEmail
from ..report import Finding
from ..severity import Severity

_SHORTENERS = frozenset(
    {
        "bit.ly",
        "t.co",
        "tinyurl.com",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "bitly.com",
        "rb.gy",
        "cutt.ly",
        "shorturl.at",
        "rebrand.ly",
        "trib.al",
        "tiny.cc",
        "soo.gd",
        "s.id",
        "lnkd.in",
    }
)

# Known multi-label public suffixes. Not exhaustive — covers most
# encountered by single-user PoC traffic. BACKLOG notes an upgrade to
# tldextract when false-positives surface.
_MULTI_LABEL_TLDS = frozenset(
    {
        "co.uk",
        "co.jp",
        "co.nz",
        "co.za",
        "co.in",
        "co.il",
        "co.kr",
        "com.au",
        "com.br",
        "com.mx",
        "com.cn",
        "com.sg",
        "com.tw",
        "com.hk",
        "org.uk",
        "net.au",
        "gov.uk",
        "ac.uk",
        "ac.jp",
    }
)

# Extracts something that looks like a domain out of anchor-visible text.
_DOMAIN_IN_TEXT_RX = re.compile(
    r"\b([a-z0-9][a-z0-9\-]{0,62}(?:\.[a-z0-9][a-z0-9\-]{0,62})+\.[a-z]{2,})\b",
    re.IGNORECASE,
)

# Common abbreviations we should not treat as domains even though they
# technically match "word.tld" shape.
_IGNORE_TEXT_DOMAINS = frozenset({"e.g.", "i.e.", "etc.", "mr.", "inc.", "co."})


def _registrable(host: str) -> str:
    """Return the eTLD+1 for `host`. Stdlib-only approximation: checks against
    a small known multi-label TLD list; otherwise returns the last two parts."""
    host = host.lower().strip(".")
    if not host or "." not in host:
        return host
    parts = host.split(".")
    if len(parts) >= 3:
        last_two = ".".join(parts[-2:])
        if last_two in _MULTI_LABEL_TLDS:
            return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _href_host(href: str) -> str | None:
    if not href:
        return None
    try:
        u = urlparse(href)
    except Exception:
        return None
    if u.scheme not in ("http", "https"):
        return None
    return (u.hostname or "").lower() or None


def _apparent_domain_in_text(text: str) -> str | None:
    """Best-effort extraction of a domain mentioned in visible link text."""
    if not text:
        return None
    cleaned = text.strip().strip("()[]{}.,;:\"'")
    if cleaned.lower() in _IGNORE_TEXT_DOMAINS:
        return None
    m = _DOMAIN_IN_TEXT_RX.search(cleaned)
    if not m:
        return None
    return m.group(1).lower()


async def run(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    if email.html is None:
        return findings

    soup = parse_html(email.html)
    anchors = soup.find_all("a", href=True)

    shortener_hits: list[dict] = []
    mismatch_hits: list[dict] = []

    for a in anchors:
        href = a.get("href", "") or ""
        host = _href_host(href)
        if not host:
            continue

        host_reg = _registrable(host)
        if host_reg in _SHORTENERS:
            shortener_hits.append({"host": host, "href": href[:120]})

        visible_text = a.get_text(separator=" ", strip=True)
        text_domain = _apparent_domain_in_text(visible_text)
        if text_domain:
            text_reg = _registrable(text_domain)
            if text_reg != host_reg and text_reg and host_reg:
                mismatch_hits.append(
                    {
                        "visible_domain": text_domain,
                        "href_host": host,
                        "href_registrable": host_reg,
                        "visible_text": visible_text[:120],
                        "href": href[:120],
                    }
                )

    if shortener_hits:
        findings.append(
            Finding(
                check="content.url_shortener",
                severity=Severity.MEDIUM,
                passed=False,
                message=(
                    f"{len(shortener_hits)} link(s) use URL shortener domains "
                    f"(e.g. {shortener_hits[0]['host']}). Shorteners compound "
                    f"with other spam signals and obscure destination reputation."
                ),
                details={"hits": shortener_hits[:10]},
            )
        )
    else:
        findings.append(
            Finding(
                check="content.url_shortener",
                severity=Severity.INFO,
                passed=True,
                message="No URL-shortener domains detected in links.",
            )
        )

    if mismatch_hits:
        findings.append(
            Finding(
                check="content.anchor_href_mismatch",
                severity=Severity.HIGH,
                passed=False,
                message=(
                    f"{len(mismatch_hits)} link(s) show one domain in visible "
                    f"text but link to another (classic phishing pattern)."
                ),
                details={"hits": mismatch_hits[:10]},
            )
        )
    else:
        findings.append(
            Finding(
                check="content.anchor_href_mismatch",
                severity=Severity.INFO,
                passed=True,
                message="No anchor-text / href domain mismatches detected.",
            )
        )

    return findings
