"""Parse a raw .eml into ParsedEmail using stdlib email with policy.default."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from email import message_from_bytes, policy
from email.message import EmailMessage
from email.utils import parsedate_to_datetime
from pathlib import Path


@dataclass
class ParsedEmail:
    raw: EmailMessage
    headers: dict[str, list[str]]
    html: str | None
    plain_text: str | None
    from_addr: str | None
    to_addrs: list[str]
    subject: str | None
    authentication_results: list[str]
    # Best-guess timestamp for when the email actually landed in the user's
    # inbox. Pulled from the top-most Received: header (latest hop in the
    # chain — i.e. the user's MX) when available; falls back to the Date:
    # header (sender's claim), then to None when neither parses. Distinct
    # from our ingest time (`Email.audited_at` semantics).
    received_at: datetime | None


def _parse_rfc2822_date(value: str) -> datetime | None:
    """Wrap parsedate_to_datetime, return None on any parse failure. Always
    returns a tz-aware UTC datetime when successful."""
    try:
        dt = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _extract_received_at(headers: dict[str, list[str]]) -> datetime | None:
    """Pick the best timestamp for when this email actually landed in the
    user's inbox.

    Priority:
      1. Top-most Received: header — the latest hop, which for an inbound
         email is the user's MX dropping it in their mailbox. Format is
         '<routing stuff>; Mon, 1 Jun 2026 14:30:00 +0000' — we split on
         the final ';' and parse the right-hand date.
      2. Date: header — the sender's claim of when they sent it. Less
         accurate than Received but always present.
      3. None — caller falls back to ingest time as a last resort.
    """
    # Received headers are stored in arrival order (top of file = top of
    # the stack = latest hop). We try each from the top until one parses.
    for raw in headers.get("received", []):
        # Routing block ends at the final ';'. Anything before that is
        # 'from X by Y with PROTO id …', anything after is the timestamp.
        if ";" not in raw:
            continue
        candidate = raw.rsplit(";", 1)[1].strip()
        # Trim trailing parenthetical comments like '(UTC)' that breaks
        # some date parsers in edge cases.
        candidate = candidate.split("(", 1)[0].strip()
        dt = _parse_rfc2822_date(candidate)
        if dt is not None:
            return dt

    for raw in headers.get("date", []):
        dt = _parse_rfc2822_date(raw)
        if dt is not None:
            return dt

    return None


def parse_eml(source: bytes | str | Path) -> ParsedEmail:
    if isinstance(source, (str, Path)):
        source = Path(source).read_bytes()
    msg = message_from_bytes(source, policy=policy.default)

    headers: dict[str, list[str]] = {}
    for k, v in msg.items():
        headers.setdefault(k.lower(), []).append(str(v))

    html: str | None = None
    plain: str | None = None
    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        ctype = part.get_content_type()
        if ctype == "text/html" and html is None:
            # A mail transfer agent sends CRLF. lxml normalised it on the way
            # through BeautifulSoup and every word count and newline regex
            # relied on that. The stdlib parser does not, so normalise here and
            # keep the behaviour in this repository instead of in a parser.
            html = part.get_content().replace("\r\n", "\n").replace("\r", "\n")
        elif ctype == "text/plain" and plain is None:
            plain = part.get_content()

    return ParsedEmail(
        raw=msg,
        headers=headers,
        html=html,
        plain_text=plain,
        from_addr=msg.get("From"),
        to_addrs=list(msg.get_all("To") or []),
        subject=msg.get("Subject"),
        authentication_results=headers.get("authentication-results", []),
        received_at=_extract_received_at(headers),
    )
