"""Live RFC 8058 one-click unsubscribe verification.

Header-presence is checked by `unsubscribe.py`. This check goes one
step further: actually POSTs `List-Unsubscribe=One-Click` to the URL
and verifies the server returns 2xx without an auth wall.

Two-hop tolerance: ESPs commonly return a 30x redirect from their
tracking proxy to the actual unsub backend. We follow ONE redirect.
If the terminal response is 2xx → PASS. If 4xx (especially 401/403/
405) → FAIL — recipient mail client (Gmail / Apple Mail) will fail
the same way and the sender takes a reputation hit.

This check is OPT-IN. It performs real outbound HTTPS POSTs that may
trigger an actual unsubscribe on a third-party list. `audit/runner.py`
gates it behind `probe_unsub=True`. CLI exposes `--probe-unsub`.

Timeouts: 5s per hop, 2 hops max → 10s budget. Network failures
degrade to INFO (not FAIL) so transient issues don't cap the score.
"""

from __future__ import annotations

import asyncio
import re
import urllib.error
import urllib.request

from engine.net import build_opener, is_public_http_url

from ...parse import ParsedEmail
from ...report import Finding
from ...severity import Severity

CHECK_PREFIX = "content"

_HTTPS_URL_RX = re.compile(r"<\s*(https?://[^>\s]+)\s*>", re.IGNORECASE)
_TIMEOUT_S = 5.0

# The address check and the redirect refusal live in engine/net.py. They used
# to be defined here, and the MTA-STS fetch grew its own copy of the same
# problem without one, so the guard is now in a single place that both call.
_BODY = b"List-Unsubscribe=One-Click"
_HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "EmailDeliverabilityAudit/1.0 (+rfc8058-probe)",
}


def _extract_https_url(header_value: str) -> str | None:
    """Pull first https URL out of a List-Unsubscribe header.
    Header format per RFC 2369: `<url1>, <url2>` where urls may be
    `mailto:` or `https:`. We only probe https."""
    for m in _HTTPS_URL_RX.finditer(header_value):
        url = m.group(1)
        if url.lower().startswith("https://"):
            return url
    return None


def _probe_blocking(url: str) -> dict:
    """One POST. Returns dict with status, location, error."""
    if not is_public_http_url(url):
        return {"status": None, "location": None, "error": "blocked non-public URL"}
    req = urllib.request.Request(url, data=_BODY, headers=_HEADERS, method="POST")
    try:
        # A dedicated opener, never urlopen's default: the default follows a
        # redirect to a target this function never gets to check.
        with build_opener().open(req, timeout=_TIMEOUT_S) as resp:
            return {
                "status": resp.status,
                "location": resp.headers.get("Location"),
                "error": None,
            }
    except urllib.error.HTTPError as e:
        return {
            "status": e.code,
            "location": e.headers.get("Location") if e.headers else None,
            "error": None,
        }
    except Exception as e:
        return {"status": None, "location": None, "error": str(e)[:200]}


async def _probe(url: str) -> dict:
    return await asyncio.to_thread(_probe_blocking, url)


async def run(email: ParsedEmail) -> list[Finding]:
    """OPT-IN. Returns INFO when no header / no https URL / probe fails
    at network layer. Real verdict only fires when probe gets a
    definitive HTTP response."""
    headers = email.headers.get("list-unsubscribe", [])
    if not headers:
        return [
            Finding(
                check=f"{CHECK_PREFIX}.list_unsub_live_probe",
                severity=Severity.INFO,
                passed=True,
                message="No List-Unsubscribe header: nothing to probe.",
            )
        ]

    url = _extract_https_url(headers[0])
    if not url:
        return [
            Finding(
                check=f"{CHECK_PREFIX}.list_unsub_live_probe",
                severity=Severity.INFO,
                passed=True,
                message="List-Unsubscribe has no https URL (mailto-only or malformed).",
                details={"header": headers[0][:200]},
            )
        ]

    hop1 = await _probe(url)
    hops = [{"url": url, **hop1}]

    final_status = hop1["status"]
    final_url = url

    if final_status in (301, 302, 303, 307, 308) and hop1["location"]:
        next_url = hop1["location"]
        if not next_url.lower().startswith(("http://", "https://")):
            return [
                Finding(
                    check=f"{CHECK_PREFIX}.list_unsub_live_probe",
                    severity=Severity.INFO,
                    passed=True,
                    message=f"Probe got relative redirect; not followed. Status: {final_status}.",
                    details={"hops": hops},
                )
            ]
        hop2 = await _probe(next_url)
        hops.append({"url": next_url, **hop2})
        final_status = hop2["status"]
        final_url = next_url

    if final_status is None:
        return [
            Finding(
                check=f"{CHECK_PREFIX}.list_unsub_live_probe",
                severity=Severity.INFO,
                passed=True,
                message=f"Probe failed at network layer ({hops[-1].get('error')}). Inconclusive.",
                details={"hops": hops},
            )
        ]

    if 200 <= final_status < 300:
        return [
            Finding(
                check=f"{CHECK_PREFIX}.list_unsub_live_probe",
                severity=Severity.INFO,
                passed=True,
                message=f"RFC 8058 one-click POST returned {final_status}. Endpoint reachable.",
                details={"hops": hops, "final_url": final_url},
            )
        ]

    severity = Severity.HIGH if final_status in (401, 403, 404, 405, 410) else Severity.MEDIUM
    return [
        Finding(
            check=f"{CHECK_PREFIX}.list_unsub_live_probe",
            severity=severity,
            passed=False,
            message=(
                f"RFC 8058 one-click POST failed: {final_status}. "
                "Gmail / Apple Mail will fail the same way: sender penalty likely."
            ),
            details={"hops": hops, "final_url": final_url, "final_status": final_status},
        )
    ]
