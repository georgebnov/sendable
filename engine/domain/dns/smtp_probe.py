"""MX-shape sanity + live open-relay probe.

Scope note — this module probes the **inbound** MX server. Inbound-server
behavior (connect time, banner readability, STARTTLS support) does NOT
affect outbound deliverability: Gmail / Yahoo / Microsoft do not score
your outbound mail based on how fast your inbound MX answers. The PTR /
FCrDNS check that *does* matter for deliverability lives in
`sending_ip_dns.py` and operates on the **sending IP extracted from
Received headers**, not the MX IP.

Kept here:
  - `smtp.dns_resolution` — MX must exist (bounce handling, DMARC reports).
  - `smtp.null_mx` — RFC 7505: domain explicitly accepts no mail.
  - `smtp.mx_bare_ip` — RFC 1035/5321 forbids IP literals in MX.
  - `smtp.mx_cname_violation` — RFC 2181 §10.3 forbids CNAME as MX target.
  - `smtp.open_relay` — CRITICAL: accepting off-domain RCPT TO destroys
    reputation. Probe is single MAIL FROM / RCPT TO / RSET; nothing is
    ever sent (no DATA).

Removed (was being scored against deliverability; correctness issue):
  - `smtp.connect`, `smtp.transaction_time`, `smtp.banner` — inbound-MX
    operational metrics, not deliverability signals.
  - `smtp.tls` (STARTTLS on inbound MX) — checks whether you can RECEIVE
    over TLS, not whether you SEND over TLS. Misleading.
  - `smtp.reverse_dns_resolution / mismatch`, `smtp.banner_vs_ptr` —
    these checked the MX IP, but Gmail/MS check the sending IP. Moved
    to `sending_ip_dns.py` against the Received-extracted IP.
"""

from __future__ import annotations

import asyncio
import re
import smtplib
import ssl

from engine.net import is_public_address

from ...report import Finding
from ...severity import Severity
from ..dns_client import query

_PROBE_TIMEOUT = 8.0
_OPEN_RELAY_PROBE_FROM = "audit-probe@example.invalid"
_OPEN_RELAY_PROBE_TO = "audit-probe@example.com"


def _open_relay_probe_blocking(host: str) -> dict:
    """Connect to `host` on 25 and see whether it relays for a stranger.

    The host comes from the audited domain's MX records, which whoever controls
    that domain chooses. An MX of 169.254.169.254 made this connect to the cloud
    metadata address, so the address is checked before any socket is opened. Same
    guard as the unsubscribe probe and the MTA-STS fetch; this was the third place
    the class appeared.
    """
    if not is_public_address(host):
        # Same shape as an inconclusive probe: open_relay is None because nothing
        # was established, and the error says why no connection was made.
        return {"open_relay": None, "error": "blocked_non_public_host"}
    return _open_relay_probe_unguarded(host)


def _open_relay_probe_unguarded(host: str) -> dict:
    """Single open-relay test against `host:25`. Returns dict with:
      - open_relay: True (accepted), False (rejected), or None (inconclusive)
      - error: connection/protocol error string, or None
    Probe sequence: connect → EHLO → MAIL FROM (off-domain) → RCPT TO
    (off-domain) → RSET. No DATA, so nothing is ever sent."""
    out: dict = {"open_relay": None, "error": None}
    try:
        with smtplib.SMTP(host, 25, timeout=_PROBE_TIMEOUT) as s:
            try:
                code, _ = s.ehlo()
                if code != 250:
                    out["error"] = f"ehlo:code={code}"
                    return out
            except Exception as e:
                out["error"] = f"ehlo:{type(e).__name__}"
                return out
            try:
                code_from, _ = s.docmd("MAIL", f"FROM:<{_OPEN_RELAY_PROBE_FROM}>")
                if code_from in (250, 251):
                    code_to, _ = s.docmd("RCPT", f"TO:<{_OPEN_RELAY_PROBE_TO}>")
                    out["open_relay"] = code_to in (250, 251)
                    s.docmd("RSET")
                else:
                    out["open_relay"] = False
            except Exception:
                out["open_relay"] = None
    except (OSError, smtplib.SMTPException, ssl.SSLError) as e:
        out["error"] = f"connect:{type(e).__name__}:{e}"
    except Exception as e:
        out["error"] = f"error:{type(e).__name__}"
    return out


async def _open_relay_probe(host: str) -> dict:
    return await asyncio.to_thread(_open_relay_probe_blocking, host)


def _is_null_mx(record: str) -> bool:
    """True when this MX record is RFC 7505's "accepts no mail" declaration.

    Accepts both the form dns_client produces, "0 " with the trailing dot already
    stripped, and the raw "0 ." in case a caller passes an unprocessed record.
    """
    preference, _, exchange = record.strip().partition(" ")
    if preference != "0":
        return False
    return exchange.strip().rstrip(".") == ""


async def run(domain: str) -> list[Finding]:
    findings: list[Finding] = []
    mx_ans = await query(domain, "MX")
    if not mx_ans.ok or not mx_ans.records:
        findings.append(
            Finding(
                check="smtp.dns_resolution",
                severity=Severity.HIGH,
                passed=False,
                message=f"No MX records for {domain}.",
                details={"dns_error": mx_ans.error},
            )
        )
        return findings

    findings.append(
        Finding(
            check="smtp.dns_resolution",
            severity=Severity.INFO,
            passed=True,
            message=f"{len(mx_ans.records)} MX record(s) for {domain}.",
            details={"mx": list(mx_ans.records)[:5]},
        )
    )

    # Null MX (RFC 7505): a single MX of preference 0 whose target is the root,
    # which declares that this domain accepts no mail. That is a deliberate and
    # correct configuration, not a fault.
    #
    # The test used to look for a literal " ." and never fired. dns_client formats
    # an MX as "<preference> <exchange>" and strips the trailing dot, so a null MX
    # arrives as "0 " with an empty exchange. The domain was therefore audited as
    # if it had a mail server: the per-host findings read ": not a bare IP
    # literal." with nothing before the colon, and the open-relay probe opened a
    # connection to the empty hostname.
    if len(mx_ans.records) == 1 and _is_null_mx(mx_ans.records[0]):
        findings.append(
            Finding(
                check="smtp.null_mx",
                severity=Severity.INFO,
                passed=True,
                message=(
                    f"{domain} declares that it accepts no mail at all. That is a "
                    "deliberate setting, not a fault. The audit skipped the inbound "
                    "mail server checks."
                ),
                details={"mx": mx_ans.records[0]},
            )
        )
        return findings

    def _pref(rec: str) -> int:
        try:
            return int(rec.split(" ", 1)[0])
        except (ValueError, IndexError):
            return 999

    mx_records_sorted = sorted(mx_ans.records, key=_pref)
    mx_hosts = [(m.split(" ", 1)[1] if " " in m else m).rstrip(".") for m in mx_records_sorted]

    per_host_findings = await asyncio.gather(*[_audit_mx_host(mx_host) for mx_host in mx_hosts])
    for host_f in per_host_findings:
        findings.extend(host_f)
    return findings


async def _audit_mx_host(mx_host: str) -> list[Finding]:
    """Per-MX-host findings: MX-shape sanity + open-relay probe only.
    PTR / FCrDNS moved to sending_ip_dns.py (operates on actual sending
    IP, not MX IP). Connect-time / banner / STARTTLS removed — inbound
    MX operational metrics, not deliverability signals."""
    findings: list[Finding] = []

    if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", mx_host):
        findings.append(
            Finding(
                check="smtp.mx_bare_ip",
                severity=Severity.HIGH,
                passed=False,
                message=(
                    f"Your mail server record points at the raw address {mx_host!r} "
                    "instead of a hostname. The standard forbids this, and strict "
                    "receivers reject mail from a domain that does it. Give your DNS "
                    "provider a hostname."
                ),
                details={"mx_host": mx_host},
            )
        )
    else:
        findings.append(
            Finding(
                check="smtp.mx_bare_ip",
                severity=Severity.INFO,
                passed=True,
                message=f"{mx_host}: not a bare IP literal.",
                details={"mx_host": mx_host},
            )
        )

    cname_ans = await query(mx_host, "CNAME")
    if cname_ans.ok and cname_ans.records:
        findings.append(
            Finding(
                check="smtp.mx_cname_violation",
                severity=Severity.MEDIUM,
                passed=False,
                message=(
                    f"Your mail server record points at {mx_host}, which is an alias "
                    f"for {cname_ans.records[0]!r}. A mail server record must name the "
                    "server directly, never an alias. Some receivers reject or delay "
                    "mail because of it. Point the record at the real hostname."
                ),
                details={"mx_host": mx_host, "cname_to": list(cname_ans.records)},
            )
        )
    else:
        findings.append(
            Finding(
                check="smtp.mx_cname_violation",
                severity=Severity.INFO,
                passed=True,
                message=f"{mx_host}: not a CNAME.",
                details={"mx_host": mx_host},
            )
        )

    probe = await _open_relay_probe(mx_host)
    if probe["open_relay"] is True:
        findings.append(
            Finding(
                check="smtp.open_relay",
                severity=Severity.CRITICAL,
                passed=False,
                message=(
                    f"{mx_host} accepted off-domain RCPT TO; appears to be an open "
                    "relay. Major reputation hit."
                ),
            )
        )
    elif probe["open_relay"] is False:
        findings.append(
            Finding(
                check="smtp.open_relay",
                severity=Severity.INFO,
                passed=True,
                message=f"{mx_host} rejected open-relay probe.",
            )
        )
    else:
        findings.append(
            Finding(
                check="smtp.open_relay",
                severity=Severity.INFO,
                passed=True,
                message=(
                    f"{mx_host} open-relay probe inconclusive "
                    f"({probe.get('error') or 'no response'})."
                ),
            )
        )

    return findings
