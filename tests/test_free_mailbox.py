"""Free-mailbox detection + score calibration.

A personal-mailbox sender can't authenticate a domain they don't own, so the
audit drops the auth / domain-record findings and recalibrates the score over
the categories they control — instead of hard-gating to 30 / UNHEALTHY.
"""

from engine.free_mailbox import (
    ADVISORY_CHECK,
    calibrate_for_free_mailbox,
    is_free_mailbox,
)
from engine.report import Finding
from engine.scoring import HARD_GATE_FLOOR, score_findings
from engine.severity import Severity


def test_is_free_mailbox_detects_consumer_providers():
    assert is_free_mailbox("frank.capicotto@gmail.com") == "gmail.com"
    assert is_free_mailbox("Frank Capicotto <frank@yahoo.com>") == "yahoo.com"
    assert is_free_mailbox("X@OUTLOOK.COM") == "outlook.com"


def test_is_free_mailbox_ignores_owned_and_junk():
    assert is_free_mailbox("hello@acme.com") is None
    assert is_free_mailbox("no-at-sign") is None
    assert is_free_mailbox("") is None
    assert is_free_mailbox(None) is None


def _auth_gate():
    return Finding(
        check="auth.alignment",
        severity=Severity.HIGH,
        passed=False,
        hard_gate=True,
        message="Neither DKIM nor SPF aligns with From organizational domain.",
    )


def _domain_finding():
    return Finding(
        check="dmarc_record.policy_enabled",
        severity=Severity.MEDIUM,
        passed=False,
        message="DMARC policy is p=none.",
    )


def _clean_hygiene():
    return Finding(
        check="content.required_headers",
        severity=Severity.INFO,
        passed=True,
        message="All required headers present.",
    )


def test_calibration_drops_auth_and_adds_advisory_for_free_mailbox():
    findings = [_auth_gate(), _domain_finding(), _clean_hygiene()]
    out = calibrate_for_free_mailbox(findings, "frank@gmail.com")

    checks = {f.check for f in out}
    assert "auth.alignment" not in checks
    assert "dmarc_record.policy_enabled" not in checks
    assert "content.required_headers" in checks  # controllable category kept
    assert ADVISORY_CHECK in checks
    advisory = next(f for f in out if f.check == ADVISORY_CHECK)
    assert advisory.details["from_domain"] == "gmail.com"


def test_calibration_lifts_hard_gate_for_free_mailbox():
    findings = [_auth_gate(), _clean_hygiene()]

    # Before: the auth hard-gate floors the score to 30 / NO_GO.
    before = score_findings(findings)
    assert before["verdict"] == "NO_GO"
    assert before["score"] <= HARD_GATE_FLOOR

    # After: calibrated for a gmail sender, no hard-gate. The auth / domain
    # categories carry no findings so they neutralise to 100 (no drag) instead
    # of flooring the composite.
    after = score_findings(calibrate_for_free_mailbox(findings, "frank@gmail.com"))
    assert after["sub_scores"]["authentication"] == 100
    assert after["sub_scores"]["domain_records"] == 100
    assert after["verdict"] != "NO_GO"
    assert after["score"] > HARD_GATE_FLOOR


def test_calibration_noop_for_owned_domain():
    findings = [_auth_gate(), _domain_finding(), _clean_hygiene()]
    out = calibrate_for_free_mailbox(findings, "hello@acme.com")
    assert out is findings  # unchanged — common case untouched
    assert all(f.check != ADVISORY_CHECK for f in out)
