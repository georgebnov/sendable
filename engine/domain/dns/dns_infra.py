"""DNS infrastructure: NS records only.

Scope is deliberately tight. Receivers (Gmail / Microsoft / Yahoo) check
forward+reverse DNS on the *sending IP* (handled in `smtp_probe.py` and
`auth.py`), not the sender domain's zone administration. SOA values,
nameserver redundancy, and serial format are DNS-ops hygiene — they do
not affect inbox placement.

Kept: NS records published — if NS is absent, DNS is broken and nothing
downstream (SPF / DKIM / DMARC / MX) can resolve.

Removed (was MEDIUM, was scoring against deliverability — see git history
for `at_least_two_servers`, `all_servers_responding`, `soa_present`,
`soa_refresh`, `soa_retry`, `soa_expire`, `soa_nxdomain_ttl`,
`soa_serial_format`). If we ever want a separate DNS-ops module, those
belong there, not in the deliverability report.
"""

from __future__ import annotations

from ...report import Finding
from ...severity import Severity
from ..dns_client import query

CHECK_PREFIX = "dns"


async def run(domain: str) -> list[Finding]:
    findings: list[Finding] = []

    ns_ans = await query(domain, "NS")
    if not ns_ans.ok or not ns_ans.records:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.ns_records_published",
            severity=Severity.HIGH,
            passed=False,
            message=f"No NS records for {domain}.",
            details={"dns_error": ns_ans.error},
        ))
        return findings

    nameservers = [r.rstrip(".") for r in ns_ans.records]
    findings.append(Finding(
        check=f"{CHECK_PREFIX}.ns_records_published",
        severity=Severity.INFO,
        passed=True,
        message=f"{len(nameservers)} NS record(s) for {domain}.",
        details={"nameservers": nameservers},
    ))

    return findings
