"""policy_engine — recipient-side gateways never appear in 'authenticate X'.

A gateway/forwarder breaks DKIM by design and has no sender-side fix, so it
must be kept out of the fix/ease instruction. But a pure-gateway bleed still
gets the calm 'expected, nothing to fix' reassurance.
"""

from __future__ import annotations

from engine.dmarc.policy_engine import (
    DmarcRecord,
    Sender,
    SpfRecord,
    Window,
    evaluate,
)

_RUA = "rua+reports@inboxhealth.app"


def _s(name, classification, legitimacy, *, dispo="reject", aligned=False, vol=3):
    return Sender(
        name,
        vol,
        aligned,
        aligned,
        aligned,
        aligned,
        legitimacy,
        dispo,
        classification=classification,
    )


def _decide(senders):
    window = Window(senders=senders, clean_streak_days=0, days_with_data=10, total_volume=60)
    rec = DmarcRecord(True, "reject", pct=50)
    spf = SpfRecord(True, 1, 6, "-")
    return evaluate(rec, spf, window, _RUA).ladder_decision


def test_gateway_kept_out_of_authenticate_instruction():
    d = _decide(
        [
            _s("Microsoft 365", "clean", "legit", dispo="none", aligned=True, vol=50),
            _s("Avanan (Check Point)", "gateway_relay", "legit"),
            _s("Your ESP", "sender_auth_gap", "unconfirmed"),
        ]
    )
    text = f"{d.detail} {d.suggested_action}"
    assert "Your ESP" in text  # the fixable sender is named
    assert "Avanan" not in text  # the gateway is not
    assert d.new_record is None  # no domain rollback for one fixable source


def test_pure_gateway_bleed_still_reassures():
    d = _decide(
        [
            _s("Microsoft 365", "clean", "legit", dispo="none", aligned=True, vol=50),
            _s("Avanan (Check Point)", "gateway_relay", "legit"),
        ]
    )
    assert d.code == "FORWARD_BLEED_OK"
    assert d.new_record is None
