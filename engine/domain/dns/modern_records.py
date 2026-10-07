"""Modern records: MTA-STS, TLSRPT, BIMI.

Scope note — these are NOT outbound deliverability factors:

  - MTA-STS governs TLS enforcement for **inbound** mail to your domain.
    It tells other senders "encrypt SMTP to me or don't deliver." Gmail
    and Microsoft do not score outbound mail lower for missing or broken
    MTA-STS. Treat as inbound security hardening.
  - TLSRPT is a **reporting** mechanism for inbound TLS failures. Same
    class as MTA-STS — operationally useful, not a deliverability lever.
  - BIMI is a brand-logo display feature (Gmail/Apple). Optional; pure
    upside, no penalty for absence.

All three are kept because they reflect operator hygiene and are easy
DNS / HTTPS lookups. But severities are kept LOW/INFO so they don't
inflate the deliverability score against a sender who is, in fact,
delivering fine. Framing in messages calls out the scope explicitly.

Lookups: TXT at well-known subdomains. MTA-STS additionally fetches the
HTTPS policy file. BIMI cert/image validation deferred (BACKLOG).
"""

from __future__ import annotations

import asyncio
import re
import ssl
import urllib.error
import urllib.request

from ...report import Finding
from ...severity import Severity
from ..dns_client import query

_MTA_STS_PREFIX_RX = re.compile(r"^\s*v\s*=\s*STSv1\b", re.IGNORECASE)
_TLSRPT_PREFIX_RX = re.compile(r"^\s*v\s*=\s*TLSRPTv1\b", re.IGNORECASE)
_BIMI_PREFIX_RX = re.compile(r"^\s*v\s*=\s*BIMI1\b", re.IGNORECASE)
_DMARC_PREFIX_RX = re.compile(r"^\s*v\s*=\s*DMARC1\b", re.IGNORECASE)
_DMARC_P_RX = re.compile(r"\bp\s*=\s*(none|quarantine|reject)\b", re.IGNORECASE)

_MTA_STS_VALID_MODES = ("enforce", "testing", "none")
_HTTPS_TIMEOUT = 5.0


# ─── MTA-STS ────────────────────────────────────────────────────────────


async def _fetch_mta_sts_policy(domain: str) -> tuple[str | None, str | None]:
    """HTTPS GET the policy file. Returns (text, error)."""
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"

    def _do() -> tuple[str | None, str | None]:
        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(url, headers={"User-Agent": "audit/0.0.1"})
            with urllib.request.urlopen(req, timeout=_HTTPS_TIMEOUT, context=ctx) as resp:
                ctype = resp.headers.get("Content-Type", "")
                body = resp.read(8192).decode("utf-8", errors="replace")
                if "text/plain" not in ctype:
                    return body, f"content_type:{ctype}"
                return body, None
        except urllib.error.HTTPError as e:
            return None, f"http_{e.code}"
        except urllib.error.URLError as e:
            return (
                None,
                f"url_error:{type(e.reason).__name__ if hasattr(e, 'reason') else 'unknown'}",
            )
        except ssl.SSLError as e:
            return None, f"ssl_error:{type(e).__name__}"
        except Exception as e:
            return None, f"error:{type(e).__name__}"

    return await asyncio.to_thread(_do)


def _parse_mta_sts_policy(text: str) -> tuple[dict[str, list[str]], list[str]]:
    """Parse policy file. Returns (kv-map, syntax_issues). Repeated `mx:`
    lines accumulate into a list."""
    kv: dict[str, list[str]] = {}
    issues: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if ":" not in line:
            issues.append(f"line missing ':' — '{line[:40]}'")
            continue
        key, _, val = line.partition(":")
        kv.setdefault(key.strip().lower(), []).append(val.strip())
    if "version" not in kv or kv["version"][0].upper() != "STSV1":
        issues.append("policy must start with 'version: STSv1'")
    if "mode" not in kv:
        issues.append("missing 'mode:'")
    elif kv["mode"][0].lower() not in _MTA_STS_VALID_MODES:
        issues.append(f"mode='{kv['mode'][0]}' not in {_MTA_STS_VALID_MODES}")
    if "max_age" not in kv:
        issues.append("missing 'max_age:'")
    if "mx" not in kv:
        issues.append("no 'mx:' entries")
    return kv, issues


async def _run_mta_sts(domain: str) -> list[Finding]:
    findings: list[Finding] = []
    qname = f"_mta-sts.{domain}"
    ans = await query(qname, "TXT")
    records = [r for r in ans.records if _MTA_STS_PREFIX_RX.match(r)] if ans.ok else []

    if not records:
        # Severity INFO (was LOW): the finding's own description says this
        # isn't a deliverability factor. Deducting points for something we
        # explicitly tell the user doesn't matter was internally inconsistent.
        # Surface it as awareness, not a penalty.
        findings.append(
            Finding(
                check="mta_sts.published",
                severity=Severity.INFO,
                passed=True,
                message=(
                    f"No MTA-STS record at {qname}. Inbound security hardening, "
                    "not an outbound deliverability factor — Gmail/Microsoft do "
                    "not penalize spam scoring for missing MTA-STS. Optional."
                ),
                details={"dns_error": ans.error},
            )
        )
        return findings

    findings.append(
        Finding(
            check="mta_sts.published",
            severity=Severity.INFO,
            passed=True,
            message=f"MTA-STS record at {qname}.",
            details={"record": records[0][:200]},
        )
    )

    if len(records) > 1:
        findings.append(
            Finding(
                check="mta_sts.multiple_records",
                severity=Severity.LOW,
                passed=False,
                message=(
                    f"{len(records)} MTA-STS records found (inbound TLS policy "
                    "broken). Does not affect outbound deliverability."
                ),
            )
        )
    else:
        findings.append(
            Finding(
                check="mta_sts.multiple_records",
                severity=Severity.INFO,
                passed=True,
                message="Single MTA-STS record.",
            )
        )

    rec = records[0]
    syntax_issues: list[str] = []
    has_id = bool(re.search(r"\bid\s*=\s*\S+", rec))
    if not has_id:
        syntax_issues.append("missing 'id=' tag")
    if syntax_issues:
        findings.append(
            Finding(
                check="mta_sts.syntax",
                severity=Severity.LOW,
                passed=False,
                message=(
                    f"MTA-STS record syntax: {'; '.join(syntax_issues)}. "
                    "Inbound TLS policy hygiene; not a deliverability factor."
                ),
            )
        )
    else:
        findings.append(
            Finding(
                check="mta_sts.syntax",
                severity=Severity.INFO,
                passed=True,
                message="MTA-STS record syntax OK.",
            )
        )

    policy_text, fetch_error = await _fetch_mta_sts_policy(domain)
    if policy_text is None:
        findings.append(
            Finding(
                check="mta_sts.policy_fetch",
                severity=Severity.LOW,
                passed=False,
                message=(
                    f"MTA-STS policy file not retrievable: {fetch_error}. "
                    "Inbound TLS enforcement is broken for senders that honor "
                    "MTA-STS, but does not affect your outbound deliverability."
                ),
            )
        )
        return findings

    findings.append(
        Finding(
            check="mta_sts.policy_fetch",
            severity=Severity.INFO,
            passed=True,
            message="MTA-STS policy file retrieved.",
        )
    )

    _, policy_issues = _parse_mta_sts_policy(policy_text)
    if policy_issues:
        findings.append(
            Finding(
                check="mta_sts.policy_syntax",
                severity=Severity.LOW,
                passed=False,
                message=(
                    f"MTA-STS policy syntax: {'; '.join(policy_issues[:3])}. "
                    "Inbound TLS policy hygiene; not a deliverability factor."
                ),
                details={"issues": policy_issues},
            )
        )
    else:
        findings.append(
            Finding(
                check="mta_sts.policy_syntax",
                severity=Severity.INFO,
                passed=True,
                message="MTA-STS policy syntax OK.",
            )
        )

    return findings


# ─── TLSRPT ─────────────────────────────────────────────────────────────


async def _run_tlsrpt(domain: str) -> list[Finding]:
    findings: list[Finding] = []
    qname = f"_smtp._tls.{domain}"
    ans = await query(qname, "TXT")
    records = [r for r in ans.records if _TLSRPT_PREFIX_RX.match(r)] if ans.ok else []

    if not records:
        # Severity INFO (was LOW) — same reasoning as MTA-STS above.
        # The finding's own description says it isn't a deliverability
        # factor, so it shouldn't deduct points either.
        findings.append(
            Finding(
                check="tlsrpt.published",
                severity=Severity.INFO,
                passed=True,
                message=(
                    f"No TLSRPT record at {qname}. TLSRPT is a reporting "
                    "mechanism for inbound TLS failures — not an outbound "
                    "deliverability factor. Optional ops visibility only."
                ),
                details={"dns_error": ans.error},
            )
        )
        return findings

    findings.append(
        Finding(
            check="tlsrpt.published",
            severity=Severity.INFO,
            passed=True,
            message=f"TLSRPT record at {qname}.",
            details={"record": records[0][:200]},
        )
    )

    if len(records) > 1:
        findings.append(
            Finding(
                check="tlsrpt.multiple_records",
                severity=Severity.LOW,
                passed=False,
                message=(
                    f"{len(records)} TLSRPT records found. Inbound TLS reporting "
                    "hygiene; not a deliverability factor."
                ),
            )
        )
    else:
        findings.append(
            Finding(
                check="tlsrpt.multiple_records",
                severity=Severity.INFO,
                passed=True,
                message="Single TLSRPT record.",
            )
        )

    rec = records[0]
    if "rua=" not in rec.lower():
        findings.append(
            Finding(
                check="tlsrpt.syntax",
                severity=Severity.LOW,
                passed=False,
                message=(
                    "TLSRPT record missing rua= tag (no report destination). "
                    "Inbound TLS reporting hygiene; not a deliverability factor."
                ),
            )
        )
    else:
        findings.append(
            Finding(
                check="tlsrpt.syntax",
                severity=Severity.INFO,
                passed=True,
                message="TLSRPT record syntax OK.",
            )
        )

    return findings


# ─── BIMI ───────────────────────────────────────────────────────────────


async def _dmarc_policy(domain: str) -> str | None:
    """Current DMARC enforcement level (none|quarantine|reject), or None when
    no DMARC record is published. BIMI is only honoured at quarantine/reject."""
    ans = await query(f"_dmarc.{domain}", "TXT")
    if not ans.ok:
        return None
    for r in ans.records:
        if _DMARC_PREFIX_RX.match(r):
            m = _DMARC_P_RX.search(r)
            return m.group(1).lower() if m else "none"
    return None


async def _run_bimi(domain: str) -> list[Finding]:
    """BIMI lives at default._bimi.<domain> by default. v1 only checks the
    DNS record + l= / a= tag presence. Cert/image fetch is BACKLOG."""
    findings: list[Finding] = []
    qname = f"default._bimi.{domain}"
    ans = await query(qname, "TXT")
    records = [r for r in ans.records if _BIMI_PREFIX_RX.match(r)] if ans.ok else []

    if not records:
        policy = await _dmarc_policy(domain)
        eligible = policy in ("quarantine", "reject")
        if not eligible:
            # BIMI is ignored below enforcement — don't hand out a record that
            # can't work yet. Point them at the prerequisite instead.
            findings.append(
                Finding(
                    check="bimi.published",
                    severity=Severity.INFO,
                    passed=False,
                    message=(
                        f"No BIMI logo record. BIMI only works once your DMARC "
                        f"policy is at quarantine or reject (you're at "
                        f"p={policy or 'none'}). Move your DMARC up first, then add "
                        f"the logo record."
                    ),
                    details={
                        "dns_error": ans.error,
                        "dmarc_policy": policy,
                        "eligible": False,
                    },
                )
            )
            return findings

        suggested = f"v=BIMI1; l=https://{domain}/bimi/logo.svg;"
        findings.append(
            Finding(
                check="bimi.published",
                severity=Severity.INFO,
                passed=False,
                message=(
                    f"No BIMI record at {qname} (optional — Gmail/Apple logo bonus). "
                    f"You're at p={policy}, so you're eligible. Add a TXT record at "
                    f"{qname} with this value: {suggested} — point l= at a square "
                    f"SVG (SVG Tiny PS profile) logo you host over HTTPS. To actually "
                    f"display the logo, Gmail and Apple also require a Verified Mark "
                    f"Certificate (VMC), added as a=https://your-host/vmc.pem."
                ),
                details={
                    "dns_error": ans.error,
                    "dmarc_policy": policy,
                    "eligible": True,
                    "record_host": qname,
                    "suggested_record": suggested,
                },
            )
        )
        return findings

    findings.append(
        Finding(
            check="bimi.published",
            severity=Severity.INFO,
            passed=True,
            message=f"BIMI record at {qname}.",
            details={"record": records[0][:200]},
        )
    )

    rec = records[0]
    syntax_issues: list[str] = []
    if "l=" not in rec.lower():
        syntax_issues.append("missing 'l=' (logo URL)")
    elif not re.search(r"l\s*=\s*https://", rec, re.IGNORECASE):
        syntax_issues.append("'l=' must be https://")
    if syntax_issues:
        findings.append(
            Finding(
                check="bimi.syntax",
                severity=Severity.MEDIUM,
                passed=False,
                message=f"BIMI syntax: {'; '.join(syntax_issues)}",
            )
        )
    else:
        findings.append(
            Finding(
                check="bimi.syntax",
                severity=Severity.INFO,
                passed=True,
                message="BIMI syntax OK.",
            )
        )

    return findings


# ─── public ─────────────────────────────────────────────────────────────


async def run(domain: str) -> list[Finding]:
    mta_sts_f, tlsrpt_f, bimi_f = await asyncio.gather(
        _run_mta_sts(domain),
        _run_tlsrpt(domain),
        _run_bimi(domain),
    )
    return [*mta_sts_f, *tlsrpt_f, *bimi_f]
