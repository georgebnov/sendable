"""Reverse DNS on the address that actually delivered the message.

Every receiving provider asks the same question of the delivering address: what
is your name, and does that name point back here? The answer lives on the IP
that handed the message to the receiver's MX, which is the ESP's machine
whenever an ESP is in the path, not the sender's own MX.

Gmail's sender FAQ puts broken forward/reverse DNS in the row that earns
"Temporary or Permanent Failure codes, or spam foldering", and the code it sends
is 550 5.7.25. The two failing findings name that code, because a sender reading
"penalised" looks in the spam folder for a message that was never accepted.
"""

from __future__ import annotations

import re

from engine.domain.dns import sending_ip_dns

from .conftest import FakeDns

_RECEIVED = [
    "from mail.example.net (mail.example.net [198.51.100.7]) by mx.google.com "
    "with ESMTPS id abc; Mon, 1 Jun 2026 14:30:00 +0000",
]


def _headers() -> dict[str, list[str]]:
    return {"received": list(_RECEIVED)}


async def test_a_round_tripping_name_passes(dns: FakeDns) -> None:
    dns.set("7.100.51.198.in-addr.arpa", "PTR", "mail.example.net")
    dns.set("mail.example.net", "A", "198.51.100.7")
    findings = await sending_ip_dns.run(_headers())
    by_check = {f.check: f for f in findings}
    assert by_check["sending_ip.ptr_resolves"].passed
    assert by_check["sending_ip.fcrdns"].passed


async def test_a_missing_name_names_the_rejection_code(dns: FakeDns) -> None:
    # No PTR registered, so the reverse lookup answers NXDOMAIN.
    findings = await sending_ip_dns.run(_headers())
    f = next(f for f in findings if f.check == "sending_ip.ptr_resolves")
    assert not f.passed
    assert "550 5.7.25" in f.message
    # The consequence has to be refusal, not a worse folder. A sender who reads
    # "penalised" goes looking in spam for a message that was never accepted.
    # Both spellings, because the repo uses either one elsewhere.
    assert "refuse" in f.message
    assert not re.search(r"penali[sz]", f.message)
    # The sender cannot fix an ESP's PTR record. Say whose record it is.
    assert "sending provider" in f.message


async def test_a_name_that_does_not_point_back_names_the_rejection_code(
    dns: FakeDns,
) -> None:
    dns.set("7.100.51.198.in-addr.arpa", "PTR", "mail.example.net")
    dns.set("mail.example.net", "A", "203.0.113.9")
    findings = await sending_ip_dns.run(_headers())
    f = next(f for f in findings if f.check == "sending_ip.fcrdns")
    assert not f.passed
    assert "550 5.7.25" in f.message
    assert "refuse" in f.message
    assert not re.search(r"penali[sz]", f.message)
    # Both addresses appear, so the sender can hand the pair to their provider.
    assert "198.51.100.7" in f.message
    assert "203.0.113.9" in f.message


async def test_a_name_with_no_address_at_all_is_still_a_failure(dns: FakeDns) -> None:
    dns.set("7.100.51.198.in-addr.arpa", "PTR", "mail.example.net")
    findings = await sending_ip_dns.run(_headers())
    f = next(f for f in findings if f.check == "sending_ip.fcrdns")
    assert not f.passed
    assert "no address at all" in f.message


async def test_no_received_chain_skips_both_checks(dns: FakeDns) -> None:
    # A forwarded or ARC-rewritten message can carry no usable address. The
    # check reports why it skipped rather than reporting a failure it cannot see.
    findings = await sending_ip_dns.run({})
    assert [f.check for f in findings] == ["sending_ip.extraction"]
    assert not findings[0].passed
    assert findings[0].severity == "INFO"


async def test_the_demote_path_leaves_the_skip_note_alone(dns: FakeDns) -> None:
    """A forwarded message can detect an ESP and still have no sending IP.

    The caller demotes whenever an ESP was detected, and `esp.detect` reads the
    DKIM domain, the header names, the Feedback-ID and the body. It never reads
    the Received chain. So these two states coexist, and rewriting the skip note
    told the sender to escalate an IP that does not exist.
    """
    findings = await sending_ip_dns.run({})
    assert [f.check for f in findings] == ["sending_ip.extraction"]
    out = sending_ip_dns.demote_to_info_when_esp(findings, "SendGrid")
    assert len(out) == 1
    assert out[0].message == findings[0].message, "the skip note was rewritten"
    assert "SendGrid" not in out[0].message
    assert "deliverability team" not in out[0].message


async def test_the_demote_path_still_demotes_a_real_ip_finding(dns: FakeDns) -> None:
    # The function must keep doing its job: a marketer cannot republish reverse
    # DNS on an ESP's address, so the finding stays visible but stops scoring.
    findings = await sending_ip_dns.run(_headers())
    f = next(f for f in findings if f.check == "sending_ip.ptr_resolves")
    assert not f.passed
    out = sending_ip_dns.demote_to_info_when_esp(findings, "SendGrid")
    demoted = next(x for x in out if x.check == "sending_ip.ptr_resolves")
    assert demoted.severity == "INFO"
    assert "SendGrid" in demoted.message
    assert "deliverability team" in demoted.message


async def test_the_demote_path_does_not_touch_a_passing_finding(dns: FakeDns) -> None:
    dns.set("7.100.51.198.in-addr.arpa", "PTR", "mail.example.net")
    dns.set("mail.example.net", "A", "198.51.100.7")
    findings = await sending_ip_dns.run(_headers())
    out = sending_ip_dns.demote_to_info_when_esp(findings, "SendGrid")
    for before, after in zip(findings, out, strict=True):
        assert before.message == after.message
        assert before.severity == after.severity
