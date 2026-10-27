"""PTR / FCrDNS for the **actual sending IP**.

Gmail / Microsoft / Yahoo all require the sending IP to have a valid
PTR record that forward-resolves back to the same IP (FCrDNS — Forward
Confirmed reverse DNS). This is on the IP that handed the message to
the receiver's MX, not on the sender domain's MX server — those are
two different machines whenever an ESP (SendGrid / Mailchimp / Brevo /
Klaviyo / etc.) is in the path.

Gmail's own sender FAQ puts broken forward/reverse DNS in the row that
earns "Temporary or Permanent Failure codes, or spam foldering", and
the code it sends is 550 5.7.25. The finding says "refused", not
"penalised", because a refused message never reaches any folder and a
penalised one does.

The sending IP is extracted from the Received chain (same logic as the
RBL scan in `blacklist.py`).

Checks emitted:
  - `sending_ip.ptr_resolves` — PTR record exists for the sending IP.
  - `sending_ip.fcrdns` — Forward-resolving the PTR returns the same
    IP. This is the strict Gmail/MS requirement; PTR-without-forward
    is sometimes published by misconfigured operators.

Demoted to INFO when the sending IP belongs to a known ESP — listings
and PTR shape on a shared ESP outbound IP are not the marketer's lever
to pull. (Same pattern as the RBL scan: a HIGH finding against
SendGrid's IP misleads marketers into chasing infra they don't own.)
"""

from __future__ import annotations

from ...report import Finding
from ...severity import Severity
from ..dns_client import query, reverse_lookup
from .blacklist import extract_sender_ip


async def run(headers: dict[str, list[str]]) -> list[Finding]:
    sender_ip = extract_sender_ip(headers)
    if not sender_ip:
        return [
            Finding(
                check="sending_ip.extraction",
                severity=Severity.INFO,
                passed=False,
                message=(
                    "No sender IP recoverable from Received chain; PTR/FCrDNS "
                    "checks skipped. Common cause: message was ARC-rewritten or "
                    "forwarded before this audit ingested it."
                ),
            )
        ]

    findings: list[Finding] = [
        Finding(
            check="sending_ip.extraction",
            severity=Severity.INFO,
            passed=True,
            message=f"Sending IP extracted from Received chain: {sender_ip}.",
            details={"ip": sender_ip},
        )
    ]

    ptr_ans = await reverse_lookup(sender_ip)
    if not ptr_ans.ok or not ptr_ans.records:
        findings.append(
            Finding(
                check="sending_ip.ptr_resolves",
                severity=Severity.HIGH,
                passed=False,
                message=(
                    f"The address {sender_ip} that delivered this message has "
                    "no name. Gmail and Microsoft both require one. Gmail can "
                    "refuse the message outright for this, with the code "
                    "550 5.7.25, so it never reaches the folder at all. Your "
                    "sending provider owns this record."
                ),
                details={"ip": sender_ip, "dns_error": ptr_ans.error},
            )
        )
        return findings

    ptr = ptr_ans.records[0].rstrip(".")
    findings.append(
        Finding(
            check="sending_ip.ptr_resolves",
            severity=Severity.INFO,
            passed=True,
            message=f"PTR for sending IP {sender_ip} → {ptr}.",
            details={"ip": sender_ip, "ptr": ptr},
        )
    )

    # FCrDNS: forward-resolve the PTR hostname and confirm it returns
    # the same sending IP. Strict Gmail/MS requirement.
    fwd_ans = await query(ptr, "A")
    forward_ips = list(fwd_ans.records) if fwd_ans.ok else []
    if sender_ip in forward_ips:
        findings.append(
            Finding(
                check="sending_ip.fcrdns",
                severity=Severity.INFO,
                passed=True,
                message=(f"FCrDNS verified: PTR {ptr} forward-resolves to {sender_ip}."),
                details={"ip": sender_ip, "ptr": ptr, "forward_ips": forward_ips},
            )
        )
    else:
        findings.append(
            Finding(
                check="sending_ip.fcrdns",
                severity=Severity.HIGH,
                passed=False,
                message=(
                    f"The address {sender_ip} says its name is {ptr}, but {ptr} "
                    f"points back to {', '.join(forward_ips) or 'no address at all'}. "
                    "The name and the address have to agree in both directions. "
                    "Gmail can refuse the message outright for this, with the "
                    "code 550 5.7.25, so it never reaches the folder at all. "
                    "Microsoft checks it too. Your sending provider owns this "
                    "record."
                ),
                details={"ip": sender_ip, "ptr": ptr, "forward_ips": forward_ips},
            )
        )

    return findings


# The two checks this module runs against the sending IP. `sending_ip.extraction`
# is not one of them: it reports that no IP was recoverable, so there is no IP to
# attribute to anybody.
_IP_CHECKS = frozenset({"sending_ip.ptr_resolves", "sending_ip.fcrdns"})


def demote_to_info_when_esp(findings: list[Finding], esp_name: str) -> list[Finding]:
    """Same pattern as the RBL scan: when the sending IP belongs to a
    high-confidence ESP, demote PTR/FCrDNS findings — the marketer can't
    re-publish DNS records on SendGrid/Mailchimp/Brevo's IPs.

    Only those two findings. The caller demotes whenever an ESP was detected,
    and `esp.detect` reads the DKIM domain, the header names, the Feedback-ID
    and the body, never the Received chain. So a forwarded message can detect
    an ESP and still recover no sending IP, which leaves `sending_ip.extraction`
    failing. Rewriting that one produced "[ESP outbound IP: SendGrid] No sender
    IP recoverable ... forward the finding to their deliverability team": an IP
    that does not exist, and an escalation for a check that was skipped."""
    out: list[Finding] = []
    for f in findings:
        if f.passed or f.check not in _IP_CHECKS:
            out.append(f)
            continue
        out.append(
            f.model_copy(
                update={
                    "severity": Severity.INFO,
                    "message": (
                        f"[ESP outbound IP: {esp_name}] {f.message} "
                        f"This IP is operated by {esp_name}, not by your domain; "
                        f"forward the finding to their deliverability team."
                    ),
                    "source": "esp_owned",
                }
            )
        )
    return out
