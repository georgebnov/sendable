"""Unit tests for merge_spf + the policy-engine wiring that hands the user a
ready-to-paste SPF record for unauthorized known-ESP senders."""

from engine.dmarc.policy_engine import Sender, SpfRecord, spf_findings
from engine.dmarc.spf_merge import merge_spf

GOOGLE = "include:_spf.google.com"


# --- merge_spf: the string surgery ---------------------------------------


def test_inserts_include_before_all_and_keeps_qualifier():
    rec, warn = merge_spf("v=spf1 include:sendgrid.net -all", [GOOGLE])
    assert rec == "v=spf1 include:sendgrid.net include:_spf.google.com -all"
    assert warn is None


def test_softfail_qualifier_preserved():
    rec, _ = merge_spf("v=spf1 ~all", [GOOGLE])
    assert rec == "v=spf1 include:_spf.google.com ~all"


def test_dedupes_already_present_include_case_insensitive():
    rec, _ = merge_spf("v=spf1 INCLUDE:_SPF.GOOGLE.COM -all", [GOOGLE])
    # nothing added — record unchanged
    assert rec == "v=spf1 INCLUDE:_SPF.GOOGLE.COM -all"


def test_no_record_builds_fresh_with_default_softfail():
    rec, _ = merge_spf("", [GOOGLE])
    assert rec == "v=spf1 include:_spf.google.com ~all"


def test_missing_all_is_not_invented():
    # Published record has no `all` — we append, never flip it to enforcing.
    rec, _ = merge_spf("v=spf1 include:sendgrid.net", [GOOGLE], all_qualifier="")
    assert rec == "v=spf1 include:sendgrid.net include:_spf.google.com"
    assert "all" not in rec


def test_multiple_includes_merge_into_one_record():
    rec, _ = merge_spf("v=spf1 -all", [GOOGLE, "include:spf.protection.outlook.com"])
    assert rec == ("v=spf1 include:_spf.google.com include:spf.protection.outlook.com -all")


def test_warns_when_over_lookup_limit_but_still_returns_record():
    rec, warn = merge_spf("v=spf1 -all", [GOOGLE], current_lookups=10, lookup_limit=10)
    assert rec == "v=spf1 include:_spf.google.com -all"
    assert warn is not None and "lookup" in warn.lower()


# --- engine wiring: new_record actually reaches the finding ---------------


def _sender(name, esp_include):
    """A legit sender that fails SPF and has no aligned DKIM -> NOT_AUTHORIZED."""
    return Sender(
        name=name,
        volume=10,
        dkim_aligned=False,
        spf_aligned=False,
        spf_authpassed=False,
        has_dkim_signature=False,
        legitimacy="legit",
        disposition="none",
        esp_include=esp_include,
    )


def test_known_esp_sender_gets_paste_ready_record():
    spf = SpfRecord(exists=True, record_count=1, lookups=1, all_qualifier="-", raw="v=spf1 -all")
    findings = spf_findings(spf, [_sender("Google Workspace", GOOGLE)])
    not_auth = [f for f in findings if f.code == "SPF_SENDER_NOT_AUTHORIZED"]
    assert len(not_auth) == 1
    assert not_auth[0].new_record == "v=spf1 include:_spf.google.com -all"


def test_unknown_esp_sender_stays_text_only():
    spf = SpfRecord(exists=True, record_count=1, lookups=1, all_qualifier="-", raw="v=spf1 -all")
    findings = spf_findings(spf, [_sender("Some relay", None)])
    not_auth = [f for f in findings if f.code == "SPF_SENDER_NOT_AUTHORIZED"]
    assert len(not_auth) == 1
    # No include known -> no record handed over (would not authorize this sender).
    assert not_auth[0].new_record is None
