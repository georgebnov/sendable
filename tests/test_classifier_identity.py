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
    res = classify_record(r, _pol(), known_providers=set())
    assert res.classification == "sender_auth_gap"
    assert "Microsoft 365" in res.headline


def test_avanan_reject_is_gateway_not_spoof():
    r = _fail("203.0.113.9", "relay.avanan.net", dispo="reject")
    res = classify_record(r, _pol("reject"), known_providers=set())
    assert res.classification == "gateway_relay"


def test_perception_point_is_gateway_not_spoof():
    r = _fail("54.227.64.76", "nat.perception-point.io")
    res = classify_record(r, _pol(), known_providers=set())
    assert res.classification == "gateway_relay"


def test_known_esp_failure_is_auth_gap():
    # seout6 fails once; its provider was seen before → known, not new/spoof.
    r = _fail("192.99.215.29", "seout6.web-dns1.com")
    res = classify_record(r, _pol(), known_providers={"web-dns1.com"})
    assert res.classification == "sender_auth_gap"


def test_unknown_failure_still_spoofs_delivered():
    r = _fail("45.62.170.230", None)
    res = classify_record(r, _pol(), known_providers=set())
    assert res.classification == "spoofing_delivered"


def test_seen_unknown_ipblock_still_spoofs_not_known():
    # A spoofer's /24 fallback key having been seen before must NOT make it
    # "known" — otherwise it downgrades from spoof to auth-gap.
    r = _fail("45.62.170.230", None)
    res = classify_record(r, _pol(), known_providers={"45.62.170.0/24"})
    assert res.classification == "spoofing_delivered"


def test_unknown_failure_blocked_still_spoofs():
    r = _fail("45.62.170.230", None, dispo="reject")
    res = classify_record(r, _pol("reject"), known_providers=set())
    assert res.classification == "spoofing_blocked"


def test_recurring_known_failure_escalates():
    # Same known sender failing across prior periods = a pattern, not noise.
    r = _fail("192.99.215.29", "seout6.web-dns1.com")
    res = classify_record(
        r, _pol(), known_providers={"web-dns1.com"}, fail_history={"web-dns1.com": 2}
    )
    assert res.classification == "sender_auth_gap"
    assert "recurring" in res.headline.lower()
    assert res.severity.value in ("MEDIUM", "HIGH")


def test_one_off_known_failure_stays_low():
    r = _fail("192.99.215.29", "seout6.web-dns1.com")
    res = classify_record(r, _pol(), known_providers={"web-dns1.com"}, fail_history={})
    assert res.classification == "sender_auth_gap"
    assert "recurring" not in res.headline.lower()
    assert res.severity.value == "LOW"


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
    res = classify_record(r, _pol(), known_providers={"web-dns1.com"})
    assert res.classification == "clean"
