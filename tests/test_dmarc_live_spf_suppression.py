"""When the user has already published a provider's SPF include, the
'not in your SPF' alarm must clear from the live DNS signal — without waiting
for new DMARC reports to age the stale failing data out of the 21-day window."""

from engine.dmarc.policy_engine import (
    Sender,
    SpfRecord,
    apply_live_spf_fixes,
    spf_findings,
)


def _google_sender() -> Sender:
    # A legit Google sender the reports still show failing SPF + unaligned.
    return Sender(
        name="Google Workspace",
        volume=20,
        dkim_aligned=False,
        spf_aligned=False,
        spf_authpassed=False,
        has_dkim_signature=False,
        legitimacy="legit",
        disposition="none",
        esp_include="include:_spf.google.com",
    )


def _spf(raw: str) -> SpfRecord:
    return SpfRecord(exists=True, record_count=1, lookups=3, all_qualifier="~", raw=raw)


def _has_not_authorized(actions) -> bool:
    return any(a.code == "SPF_SENDER_NOT_AUTHORIZED" for a in actions)


def test_finding_clears_when_include_is_live():
    spf = _spf("v=spf1 include:_spf.google.com ~all")
    fixed = apply_live_spf_fixes(spf, [_google_sender()])
    assert fixed[0].spf_authpassed is True
    assert fixed[0].spf_aligned is True
    # The 'not in your SPF' card must be gone now.
    assert not _has_not_authorized(spf_findings(spf, fixed))


def test_finding_stays_when_include_absent():
    spf = _spf("v=spf1 include:spf.protection.outlook.com ~all")
    fixed = apply_live_spf_fixes(spf, [_google_sender()])
    # Untouched — Google include isn't published, so the alarm is still real.
    assert fixed[0].spf_authpassed is False
    assert _has_not_authorized(spf_findings(spf, fixed))


def test_noop_when_no_spf_published():
    spf = SpfRecord(exists=False, raw="")
    fixed = apply_live_spf_fixes(spf, [_google_sender()])
    assert fixed[0].spf_authpassed is False
