"""classify_record × sender identity (Move C).

The 2×2: a recognised sender that fails alignment is an auth gap, never a
spoof; only a genuinely unknown source that fails is a spoof. Covers every
avateq.com false-alarm plus the guard that real spoofing still fires.
"""

from __future__ import annotations

from engine.dmarc import esp_fingerprint as ef
from engine.dmarc.classifier import classify_record
from engine.dmarc.parser import DmarcPolicyPublished, DmarcRecord


def _pol(p="none"):
    return DmarcPolicyPublished(domain="avateq.com", p=p)


def _fail(ip, host, *, dispo="none"):
    ef._PTR_CACHE[ip] = host  # keep resolve_identity + classify offline
    return DmarcRecord(
        source_ip=ip,
        header_from="avateq.com",
        policy_dkim="fail",
        policy_spf="fail",
        disposition=dispo,
    )


def test_microsoft_ipv6_failure_is_auth_gap_not_impostor():
    # No PTR (like the real EOP range) → identified by CIDR, not spoof.
    r = _fail("2603:10b6:a03:2c6::201", None)
    res = classify_record(r, _pol())
    assert res.classification == "sender_auth_gap"
    assert "Microsoft 365" in res.headline


def test_avanan_reject_is_gateway_not_spoof():
    r = _fail("203.0.113.9", "relay.avanan.net", dispo="reject")
    res = classify_record(r, _pol("reject"))
    assert res.classification == "gateway_relay"


def test_perception_point_is_gateway_not_spoof():
    r = _fail("54.227.64.76", "nat.perception-point.io")
    res = classify_record(r, _pol())
    assert res.classification == "gateway_relay"


def test_a_host_nobody_recognises_reads_as_a_possible_spoof():
    # Behaviour change. This host used to read as an auth gap, but only when the
    # user happened to pass an older report that also contained it. Recognition
    # came from history, so the same sender was called a spoof or a gap
    # depending on which files were in the folder.
    #
    # Nothing is stored now, so recognition comes from the curated identities
    # alone. web-dns1.com is not one of them, and a host nobody recognises that
    # fails both checks is reported as a possible spoof. The explainer asks the
    # reader whether they recognise it, which is the honest question.
    r = _fail("192.99.215.29", "seout6.web-dns1.com")
    res = classify_record(r, _pol())
    assert res.classification == "spoofing_delivered"


def test_unknown_failure_still_spoofs_delivered():
    r = _fail("45.62.170.230", None)
    res = classify_record(r, _pol())
    assert res.classification == "spoofing_delivered"


def test_a_repeat_spoofer_cannot_promote_itself_by_appearing_twice():
    # A spoofer used to be able to downgrade itself from spoof to auth gap just
    # by turning up in an earlier report. Recognition no longer comes from
    # having been seen, so appearing twice buys nothing.
    r = _fail("45.62.170.230", None)
    assert classify_record(r, _pol()).classification == "spoofing_delivered"
    assert classify_record(r, _pol()).classification == "spoofing_delivered"


def test_unknown_failure_blocked_still_spoofs():
    r = _fail("45.62.170.230", None, dispo="reject")
    res = classify_record(r, _pol("reject"))
    assert res.classification == "spoofing_blocked"


def test_a_recognised_sender_failing_is_a_gap_and_says_so_once():
    # There used to be two severities here, one for a first failure and a higher
    # one for a sender that had failed across several reporting periods. Counting
    # periods needs a history nothing keeps, and the count depended on which
    # files the user passed, so the escalation is gone.
    #
    # The concern it came from is real, so the explainer carries it: if the same
    # sender shows up failing in report after report, fix it.
    r = _fail("2603:10b6:a03:2c6::201", None)
    res = classify_record(r, _pol())
    assert res.classification == "sender_auth_gap"
    assert "recurring" not in res.headline.lower()
    assert "report after report" in res.explainer


def test_the_severity_of_a_gap_follows_the_policy_not_a_counter():
    """Under p=none nothing is being lost yet. Under an enforcing policy the
    sender's own mail is being filtered, which is worse."""
    r = _fail("2603:10b6:a03:2c6::201", None)
    assert classify_record(r, _pol()).severity.value == "LOW"
    assert classify_record(r, _pol("quarantine")).severity.value == "MEDIUM"


def test_spf_aligned_dkim_fail_is_clean():
    # SPF aligns → DMARC passes despite DKIM failing. A legit delivery, not
    # "unclassified" (which is what the both-must-pass rule used to yield).
    ef._PTR_CACHE["203.0.113.50"] = "seout9.web-dns1.com"
    r = DmarcRecord(
        source_ip="203.0.113.50",
        header_from="avateq.com",
        policy_dkim="fail",
        policy_spf="pass",
        disposition="none",
    )
    res = classify_record(r, _pol())
    assert res.classification == "clean"
