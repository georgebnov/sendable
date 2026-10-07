"""DMARC record checks at _dmarc.<domain>.

mxtoolbox tier covered:
  - Record Published / Multiple Records / Syntax Check
  - Policy Not Enabled (p=none)
  - External Validation (rua/ruf to a different domain — that domain must
    publish a `<sender>._report._dmarc.<rua_domain>` TXT authorizing it)

Pass/fail at evaluation time is already covered by `audit.domain.auth.results.dmarc`
from the receiver's Authentication-Results.
"""

from __future__ import annotations

import re

from ...report import Finding
from ...severity import Severity
from ..dns_client import query

CHECK_PREFIX = "dmarc_record"

_DMARC_PREFIX_RX = re.compile(r"^\s*v\s*=\s*DMARC1\b", re.IGNORECASE)
_TAG_RX = re.compile(r"\s*([a-zA-Z]+)\s*=\s*([^;]+?)\s*(?:;|$)")

_VALID_TAGS = {
    "v", "p", "sp", "rua", "ruf", "adkim", "aspf",
    "pct", "fo", "rf", "ri",
}
_VALID_POLICIES = ("none", "quarantine", "reject")
_VALID_ALIGNMENT = ("r", "s")


def _parse(text: str) -> dict:
    tags = dict(_TAG_RX.findall(text))
    return {k.lower(): v.strip() for k, v in tags.items()}


def _emails_in(value: str) -> list[str]:
    """rua/ruf values are comma-separated `mailto:user@host` URIs."""
    out: list[str] = []
    for piece in value.split(","):
        piece = piece.strip()
        if piece.lower().startswith("mailto:"):
            piece = piece[7:]
        if "@" in piece:
            out.append(piece)
    return out


async def run(domain: str) -> list[Finding]:
    findings: list[Finding] = []
    qname = f"_dmarc.{domain}"
    ans = await query(qname, "TXT")
    records = [r for r in ans.records if _DMARC_PREFIX_RX.match(r)] if ans.ok else []

    # RFC 7489 §6.6.3: if no record at the queried domain, fall back to
    # the organizational domain. Required so subdomain audits inherit
    # parent policy (and parent's `sp=` applies to subdomains).
    if not records:
        from ...copywriting.link_quality import _registrable
        org_domain = _registrable(domain)
        if org_domain and org_domain != domain:
            fallback_qname = f"_dmarc.{org_domain}"
            fallback_ans = await query(fallback_qname, "TXT")
            fallback_records = [r for r in fallback_ans.records if _DMARC_PREFIX_RX.match(r)] if fallback_ans.ok else []
            if fallback_records:
                qname = fallback_qname
                ans = fallback_ans
                records = fallback_records
                findings.append(Finding(
                    check=f"{CHECK_PREFIX}.org_domain_fallback",
                    severity=Severity.INFO,
                    passed=True,
                    message=(
                        f"No DMARC at _dmarc.{domain}; inherited from "
                        f"organizational domain {org_domain} per RFC 7489 §6.6.3."
                    ),
                    details={"queried": domain, "found_at": org_domain},
                ))

    if not records:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.published",
            severity=Severity.HIGH,
            passed=False,
            message=f"No DMARC record at {qname} (and no parent org-domain record).",
            details={"dns_error": ans.error},
        ))
        return findings

    findings.append(Finding(
        check=f"{CHECK_PREFIX}.published",
        severity=Severity.INFO,
        passed=True,
        message=f"DMARC record published at {qname}.",
        details={"record": records[0][:200]},
    ))

    if len(records) > 1:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.multiple_records",
            severity=Severity.HIGH,
            passed=False,
            message=f"{len(records)} DMARC records found; receivers will ignore both.",
        ))
    else:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.multiple_records",
            severity=Severity.INFO,
            passed=True,
            message="Single DMARC record.",
        ))

    parsed = _parse(records[0])
    syntax_issues: list[str] = []
    for tag in parsed:
        if tag not in _VALID_TAGS:
            syntax_issues.append(f"unknown tag '{tag}'")
    if parsed.get("p", "").lower() not in _VALID_POLICIES:
        syntax_issues.append(f"p='{parsed.get('p')}' invalid")
    for tag in ("adkim", "aspf"):
        if tag in parsed and parsed[tag].lower() not in _VALID_ALIGNMENT:
            syntax_issues.append(f"{tag}='{parsed[tag]}' invalid")
    if "pct" in parsed:
        try:
            n = int(parsed["pct"])
            if n < 0 or n > 100:
                syntax_issues.append(f"pct={n} out of range")
        except ValueError:
            syntax_issues.append("pct not numeric")

    if syntax_issues:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.syntax",
            severity=Severity.HIGH,
            passed=False,
            message=f"DMARC syntax issues: {'; '.join(syntax_issues[:5])}",
            details={"issues": syntax_issues},
        ))
    else:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.syntax",
            severity=Severity.INFO,
            passed=True,
            message="DMARC syntax OK.",
        ))

    policy = parsed.get("p", "").lower()
    if policy == "none":
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.policy_enabled",
            severity=Severity.LOW,
            passed=False,
            message=(
                "DMARC policy is p=none (monitor-only). This meets the Gmail / "
                "Yahoo / Microsoft minimum compliance bar — your sending is "
                "technically compliant — but p=none does not protect your "
                "domain from spoofing: receivers still deliver mail that fails "
                "DMARC. Recommended upgrade path: review aggregate (rua) reports "
                "for ~30 days, then advance to p=quarantine and eventually "
                "p=reject."
            ),
            family="dmarc_policy",
        ))
    else:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.policy_enabled",
            severity=Severity.INFO,
            passed=True,
            message=f"DMARC policy enforced: p={policy}.",
        ))

    # External validation: any rua/ruf address whose domain != sender domain
    # must be authorized via `<sender>._report._dmarc.<rua-domain>` TXT.
    external_failures: list[str] = []
    for tag in ("rua", "ruf"):
        if tag not in parsed:
            continue
        for addr in _emails_in(parsed[tag]):
            rua_domain = addr.split("@", 1)[1].lower()
            if rua_domain == domain:
                continue
            authz_name = f"{domain}._report._dmarc.{rua_domain}"
            authz = await query(authz_name, "TXT")
            authorized = authz.ok and any("v=dmarc1" in r.lower() for r in authz.records)
            if not authorized:
                external_failures.append(f"{tag}:{addr}")
    if external_failures:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.external_validation",
            severity=Severity.MEDIUM,
            passed=False,
            message=(
                f"External rua/ruf domain(s) without authorization TXT: "
                f"{external_failures[:3]}. Reports won't be delivered."
            ),
            details={"failures": external_failures},
        ))
    else:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.external_validation",
            severity=Severity.INFO,
            passed=True,
            message="External rua/ruf authorization OK (or none external).",
        ))

    return findings
