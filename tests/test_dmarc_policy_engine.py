"""Engine sanity for the 5 demo cases from the spec. Each one is a known
shape — if we ever change the engine's behaviour these break loudly."""

from __future__ import annotations

from engine.dmarc.policy_engine import (
    DmarcRecord,
    Sender,
    SpfRecord,
    Window,
    evaluate,
)

RUA = "rua+reports@inboxhealth.app"


def _result_for(rec, spf, window):
    return evaluate(rec, spf, window, RUA)


def test_avateq_clean_ready_to_advance():
    """p=reject pct=50, all aligned, 25 clean days, 52 messages — ready to
    advance to pct=100. Primary should be ADVANCE with the new TXT record."""
    senders = [
        Sender(
            "Microsoft 365",
            40,
            dkim_aligned=True,
            spf_aligned=True,
            spf_authpassed=True,
            has_dkim_signature=True,
            legitimacy="legit",
            disposition="none",
        ),
        Sender(
            "Relay via megamailservers.com",
            12,
            dkim_aligned=True,
            spf_aligned=False,
            spf_authpassed=True,
            has_dkim_signature=True,
            legitimacy="legit",
            disposition="none",
        ),
    ]
    window = Window(senders=senders, days_with_data=14, total_volume=52)
    rec = DmarcRecord(True, "reject", pct=50)
    spf = SpfRecord(True, 1, 6, "-")

    result = _result_for(rec, spf, window)
    assert result.ladder_decision is not None
    assert result.ladder_decision.code == "ADVANCE"
    assert result.ladder_decision.new_record is not None
    assert "p=reject" in result.ladder_decision.new_record
    assert "pct" not in result.ladder_decision.new_record  # 100% omits pct
    assert result.blockers == []


def test_misconfigured_esp_blocks_advance():
    """Legit SendGrid with no DKIM and no SPF include → BLOCKED."""
    senders = [
        Sender("Microsoft 365", 30, True, True, True, True, "legit", "none"),
        Sender(
            "SendGrid",
            18,
            dkim_aligned=False,
            spf_aligned=False,
            spf_authpassed=False,
            has_dkim_signature=False,
            legitimacy="legit",
            disposition="none",
            esp_include="include:sendgrid.net",
        ),
    ]
    window = Window(senders=senders, days_with_data=14, total_volume=48)
    rec = DmarcRecord(True, "quarantine", pct=50)
    spf = SpfRecord(True, 1, 6, "~")

    result = _result_for(rec, spf, window)
    assert result.ladder_decision is not None
    assert result.ladder_decision.code == "BLOCKED_FIX_SENDERS"
    # A HIGH SPF finding for the unaligned legit sender should be primary.
    assert result.primary.code == "SPF_SENDER_NOT_AUTHORIZED"
    assert len(result.blockers) == 1
    assert result.blockers[0].name == "SendGrid"


def test_rollback_when_real_mail_being_rejected():
    """HubSpot legit but unauthed, currently being rejected at p=reject."""
    senders = [
        Sender(
            "HubSpot",
            22,
            dkim_aligned=False,
            spf_aligned=False,
            spf_authpassed=False,
            has_dkim_signature=False,
            legitimacy="legit",
            disposition="reject",
            esp_include="include:_spf.hubspot.com",
        ),
    ]
    window = Window(senders=senders, days_with_data=10, total_volume=22)
    rec = DmarcRecord(True, "reject", pct=100)
    spf = SpfRecord(True, 1, 9, "-")

    result = _result_for(rec, spf, window)
    assert result.ladder_decision is not None
    assert result.ladder_decision.code == "ROLLBACK"
    # ROLLBACK is so urgent it takes primary over the SPF finding.
    assert result.primary.code == "ROLLBACK"
    assert result.primary.new_record is not None
    assert "p=reject" in result.primary.new_record
    assert "pct=50" in result.primary.new_record  # step down one rung from pct=100


def test_single_low_volume_source_fixes_sender_not_policy():
    """The avateq bug: domain on p=reject pct=50, one low-volume legit source
    (2 of 52 messages) unauthenticated and being rejected. The engine must fix
    the SENDER, not roll the whole domain back — and must NOT emit a 'step down
    to p=reject' that's already in effect. No policy change (new_record None)."""
    senders = [
        Sender("Microsoft 365", 50, True, True, True, True, "legit", "none"),
        Sender(
            "HubSpot",
            2,
            dkim_aligned=False,
            spf_aligned=False,
            spf_authpassed=False,
            has_dkim_signature=False,
            legitimacy="legit",
            disposition="reject",
            esp_include="include:_spf.hubspot.com",
        ),
    ]
    window = Window(senders=senders, days_with_data=10, total_volume=52)
    rec = DmarcRecord(True, "reject", pct=50)
    spf = SpfRecord(True, 1, 9, "-")

    result = _result_for(rec, spf, window)
    assert result.ladder_decision.code == "FIX_SENDER"
    assert result.primary.code == "FIX_SENDER"
    # The policy is NOT touched — the fix lives on the sender.
    assert result.primary.new_record is None
    assert "_spf.hubspot.com" in result.primary.suggested_action
    # Never recommend the policy already in effect.
    assert "step down" not in result.primary.suggested_action.lower()


def test_low_volume_gateway_bleed_is_reassurance_not_rollback():
    """A recipient's security gateway (Avanan/Check Point) had a couple of
    messages rejected. Uncontrollable — engine reassures, never rolls the
    domain back, never tells the user to 'fix' a hop they don't own."""
    senders = [
        Sender("Microsoft 365", 48, True, True, True, True, "legit", "none"),
        Sender(
            "Avanan (Check Point)",
            3,
            dkim_aligned=False,
            spf_aligned=False,
            spf_authpassed=False,
            has_dkim_signature=False,
            legitimacy="legit",
            disposition="reject",
            classification="gateway_relay",
        ),
    ]
    window = Window(senders=senders, days_with_data=10, total_volume=51)
    rec = DmarcRecord(True, "reject", pct=50)
    spf = SpfRecord(True, 1, 6, "-")

    result = _result_for(rec, spf, window)
    assert result.ladder_decision.code == "FORWARD_BLEED_OK"
    assert result.ladder_decision.tier.value == "review"
    assert result.ladder_decision.new_record is None


def test_light_traffic_still_gets_an_answer_and_says_how_light_it_is():
    """2 messages over 2 days used to be held back with "keep collecting
    reports, we'll prompt you". Nothing collects and nothing prompts, so the
    answer is given and the size of the sample is stated for the reader."""
    senders = [
        Sender("Microsoft 365", 2, True, True, True, True, "legit", "none"),
    ]
    window = Window(senders=senders, days_with_data=2, total_volume=2)
    rec = DmarcRecord(True, "none")
    spf = SpfRecord(True, 1, 3, "-")

    result = _result_for(rec, spf, window)
    assert result.ladder_decision is not None
    assert result.ladder_decision.code == "ADVANCE"
    assert "2 day(s)" in result.ladder_decision.detail
    assert "2 message(s)" in result.ladder_decision.detail
    assert "once a month" in result.ladder_decision.detail


def test_spf_lookup_limit_outranks_ladder():
    """13 SPF lookups → PermError, HIGH severity, primary over the routine
    advance/hold."""
    senders = [
        Sender("Microsoft 365", 40, True, True, True, True, "legit", "none"),
    ]
    window = Window(senders=senders, days_with_data=14, total_volume=40)
    rec = DmarcRecord(True, "quarantine", pct=100)
    spf = SpfRecord(True, 1, 13, "-")

    result = _result_for(rec, spf, window)
    assert result.primary.code == "SPF_TOO_MANY_LOOKUPS"
    # Ladder still decides what its own answer would be (HOLD or ADVANCE).
    assert result.ladder_decision is not None
    assert result.ladder_decision.code != "SPF_TOO_MANY_LOOKUPS"
