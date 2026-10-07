"""Per-email derived columns (ported from PoC memory/derived.py).

Used by drift to compute a baseline-comparable shape for the current
email. The values overlap with what audit_service already extracts for
the emails row; drift uses this to compare against historical dicts.
"""

from __future__ import annotations

import re
from email.utils import parseaddr

from bs4 import BeautifulSoup

from engine.copywriting.link_quality import _registrable
from engine.domain.auth.results import _METHOD_RE
from engine.domain.integrity.unsubscribe import _ONE_CLICK_RX
from engine.history import EmailFacts
from engine.parse import ParsedEmail

_DMARC_POLICY_RE = re.compile(
    r"dmarc\s*=\s*[a-z]+[^;]*?\bp\s*=\s*(\w+)",
    re.IGNORECASE,
)


def _domain_of(raw_addr: str | None) -> str | None:
    if not raw_addr:
        return None
    _, mailbox = parseaddr(raw_addr)
    if not mailbox or "@" not in mailbox:
        return None
    host = mailbox.split("@", 1)[1].lower().strip()
    return host or None


def _local_of(raw_addr: str | None) -> str | None:
    if not raw_addr:
        return None
    _, mailbox = parseaddr(raw_addr)
    if not mailbox or "@" not in mailbox:
        return None
    local = mailbox.split("@", 1)[0].lower().strip()
    return local or None


def _display_name_of(raw_addr: str | None) -> str | None:
    if not raw_addr:
        return None
    name, _ = parseaddr(raw_addr)
    name = (name or "").strip().lower()
    return name or None


def _auth_results(parsed: ParsedEmail) -> dict:
    ar = parsed.authentication_results
    if not ar:
        return {
            "spf_result": None,
            "dkim_result": None,
            "dmarc_result": None,
            "dmarc_policy": None,
        }
    joined = " ".join(ar)
    results: dict[str, str] = {}
    for m in _METHOD_RE.finditer(joined):
        method, result = m.group(1).lower(), m.group(2).lower()
        results.setdefault(method, result)
    policy_match = _DMARC_POLICY_RE.search(joined)
    return {
        "spf_result": results.get("spf"),
        "dkim_result": results.get("dkim"),
        "dmarc_result": results.get("dmarc"),
        "dmarc_policy": policy_match.group(1).lower() if policy_match else None,
    }


def _unsub_flags(parsed: ParsedEmail) -> dict:
    lu = parsed.headers.get("list-unsubscribe", [])
    if lu:
        joined = " ".join(lu).lower()
        has_mailto = 1 if "<mailto:" in joined else 0
        has_https = 1 if ("<https:" in joined or "<http:" in joined) else 0
    else:
        has_mailto = None
        has_https = None
    lu_post = parsed.headers.get("list-unsubscribe-post", [])
    has_oneclick = 1 if (lu_post and _ONE_CLICK_RX.search(lu_post[0])) else (0 if lu_post else None)
    return {
        "list_unsub_has_mailto": has_mailto,
        "list_unsub_has_https": has_https,
        "list_unsub_has_oneclick_post": has_oneclick,
    }


def _count_images(html: str | None) -> int:
    if not html:
        return 0
    soup = BeautifulSoup(html, "lxml")
    return len(soup.find_all("img"))


def extract_all(parsed: ParsedEmail) -> EmailFacts:
    from_host = _domain_of(parsed.from_addr)
    reply_to = parsed.headers.get("reply-to", [])
    reply_to_raw = reply_to[0] if reply_to else None
    reply_to_host = _domain_of(reply_to_raw)

    auth = _auth_results(parsed)
    unsub = _unsub_flags(parsed)
    return EmailFacts(
        from_domain=_registrable(from_host) if from_host else None,
        from_local=_local_of(parsed.from_addr),
        display_name=_display_name_of(parsed.from_addr),
        reply_to_domain=_registrable(reply_to_host) if reply_to_host else None,
        num_images=_count_images(parsed.html),
        spf_result=auth["spf_result"],
        dkim_result=auth["dkim_result"],
        dmarc_result=auth["dmarc_result"],
        dmarc_policy=auth["dmarc_policy"],
        list_unsub_has_mailto=unsub["list_unsub_has_mailto"],
        list_unsub_has_https=unsub["list_unsub_has_https"],
        list_unsub_has_oneclick_post=unsub["list_unsub_has_oneclick_post"],
    )
