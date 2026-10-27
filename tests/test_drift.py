"""The 6 drift checks: what changed about this sender since last time.

A drift check answers a question one email cannot answer. It needs the same flat
facts for the current send and for earlier ones, and it must stay quiet until it
has enough history to tell a real change from a first sighting.

Each check is called directly rather than through the audit, because a drift
finding depends on the history passed in, and building that history is the whole
point of the test.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from engine.drift import (
    d01_dmarc_regression,
    d03_auth_flip,
    d04_dmarc_policy_downgrade,
    d08_list_unsub_regression,
    d10_display_name_rotation,
    d11_reply_to_divergence,
)
from engine.drift.runner import run_drift
from engine.history import EmailFacts
from engine.parse import ParsedEmail, parse_eml
from engine.report import Finding


def _row(**over: object) -> EmailFacts:
    """A healthy prior send. Tests override only the fields under test."""
    base: EmailFacts = {
        "from_domain": "example.com",
        "from_local": "jane",
        "display_name": "jane okafor",
        "reply_to_domain": "example.com",
        "spf_result": "pass",
        "dkim_result": "pass",
        "dmarc_result": "pass",
        "dmarc_policy": "reject",
        "list_unsub_has_mailto": 1,
        "list_unsub_has_https": 1,
        "list_unsub_has_oneclick_post": 1,
        "num_images": 1,
        "received_at": (datetime.now(UTC) - timedelta(days=2)).isoformat(),
    }
    base.update(over)  # type: ignore[typeddict-item]
    return base


def _rows(n: int, **over: object) -> list[EmailFacts]:
    out = []
    for i in range(n):
        row = _row(**over)
        row["received_at"] = (datetime.now(UTC) - timedelta(days=i + 1)).isoformat()
        out.append(row)
    return out


# d11 only evaluates bulk mail. `_is_bulk` looks for a List-Id or a campaign
# header, so this fixture carries List-Id and nothing else it does not need. It
# is built here rather than read from tests/fixtures so the drift tests do not
# move when a scoring fixture changes.
_BULK_RAW = (
    b"From: Jane Okafor <jane@example.com>\r\n"
    b"To: reader@gmail.com\r\n"
    b"Subject: March meter report\r\n"
    b"List-Id: <news.example.com>\r\n"
    b"List-Unsubscribe: <https://example.com/u/abc>\r\n"
    b"Content-Type: text/plain\r\n"
    b"\r\n"
    b"Your March water bill dropped. Unsubscribe: https://example.com/u/abc\r\n"
)


@pytest.fixture
def bulk_email() -> ParsedEmail:
    return parse_eml(_BULK_RAW)


def _one(findings: list[Finding]) -> Finding:
    assert len(findings) == 1, f"a drift check returns exactly one finding, got {len(findings)}"
    return findings[0]


def _did_not_evaluate(f: Finding) -> bool:
    """True when a check passed because it had nothing to compare, not because
    the send was clean. Each check words this differently."""
    msg = f.message.lower()
    return f.passed and any(
        phrase in msg
        for phrase in ("insufficient", "too sparse", "no dmarc policy history", "not evaluated")
    )


# ── every check stays quiet without enough history ─────────────────────────


@pytest.mark.parametrize(
    "module",
    [
        d01_dmarc_regression,
        d03_auth_flip,
        d04_dmarc_policy_downgrade,
        d08_list_unsub_regression,
        d10_display_name_rotation,
        d11_reply_to_divergence,
    ],
    ids=lambda m: m.CHECK,
)
async def test_no_check_fires_on_a_cold_start(module, bulk_email: ParsedEmail) -> None:
    # Two rows is below every threshold. A check that fires here would flag a
    # brand new sender for having no past, which is not a problem to fix.
    findings = await module.run(bulk_email, _row(), _rows(2))
    f = _one(findings)
    assert f.passed is True, f"{module.CHECK} failed a sender with almost no history"


# ── d01: DMARC regression ──────────────────────────────────────────────────


async def test_d01_quiet_when_dmarc_still_passes(bulk_email: ParsedEmail) -> None:
    f = _one(await d01_dmarc_regression.run(bulk_email, _row(), _rows(5)))
    assert f.passed is True
    assert "no regression" in f.message


async def test_d01_is_critical_when_a_clean_record_starts_failing(
    bulk_email: ParsedEmail,
) -> None:
    current = _row(dmarc_result="fail")
    f = _one(await d01_dmarc_regression.run(bulk_email, current, _rows(5)))
    assert f.passed is False
    assert f.severity == "CRITICAL"
    assert "regressed" in f.message


async def test_d01_is_high_not_critical_when_the_history_was_already_mixed(
    bulk_email: ParsedEmail,
) -> None:
    # A sender that already failed sometimes has not "regressed from clean", so
    # the finding must not claim a cleaner past than the record shows.
    history = [*_rows(3), _row(dmarc_result="fail")]
    f = _one(await d01_dmarc_regression.run(bulk_email, _row(dmarc_result="fail"), history))
    assert f.passed is False
    assert f.severity == "HIGH"


async def test_d01_treats_softfail_as_a_failure(bulk_email: ParsedEmail) -> None:
    f = _one(await d01_dmarc_regression.run(bulk_email, _row(dmarc_result="softfail"), _rows(5)))
    assert f.passed is False


# ── d03: SPF or DKIM flipping ──────────────────────────────────────────────


async def test_d03_quiet_when_both_stay_passing(bulk_email: ParsedEmail) -> None:
    f = _one(await d03_auth_flip.run(bulk_email, _row(), _rows(5)))
    assert f.passed is True
    assert "stable" in f.message


async def test_d03_flags_spf_alone(bulk_email: ParsedEmail) -> None:
    f = _one(await d03_auth_flip.run(bulk_email, _row(spf_result="fail"), _rows(10)))
    assert f.passed is False
    assert f.severity == "HIGH"
    assert "SPF regressed" in f.message


async def test_d03_flags_dkim_alone(bulk_email: ParsedEmail) -> None:
    f = _one(await d03_auth_flip.run(bulk_email, _row(dkim_result="fail"), _rows(10)))
    assert f.passed is False
    assert f.severity == "HIGH"
    assert "DKIM regressed" in f.message


async def test_d03_both_failing_together_is_critical(bulk_email: ParsedEmail) -> None:
    current = _row(spf_result="fail", dkim_result="fail")
    f = _one(await d03_auth_flip.run(bulk_email, current, _rows(10)))
    assert f.passed is False
    assert f.severity == "CRITICAL"


async def test_d03_needs_a_strong_history_before_calling_it_a_flip(
    bulk_email: ParsedEmail,
) -> None:
    # The rule is a 90% prior pass rate. A sender that failed 3 of 10 before has
    # not flipped, it is simply unreliable, and a flip finding would misname it.
    history = [*_rows(7), *[_row(spf_result="fail") for _ in range(3)]]
    f = _one(await d03_auth_flip.run(bulk_email, _row(spf_result="fail"), history))
    assert f.passed is True


# ── d04: DMARC policy weakening ────────────────────────────────────────────


async def test_d04_quiet_when_the_policy_holds(bulk_email: ParsedEmail) -> None:
    f = _one(await d04_dmarc_policy_downgrade.run(bulk_email, _row(), _rows(5)))
    assert f.passed is True


async def test_d04_flags_a_weakened_policy(bulk_email: ParsedEmail) -> None:
    # reject -> none is the downgrade that silently reopens the domain to spoofing.
    current = _row(dmarc_policy="none")
    f = _one(await d04_dmarc_policy_downgrade.run(bulk_email, current, _rows(5)))
    assert f.passed is False
    assert f.severity == "HIGH"


async def test_d04_accepts_a_strengthened_policy(bulk_email: ParsedEmail) -> None:
    history = _rows(5, dmarc_policy="none")
    f = _one(await d04_dmarc_policy_downgrade.run(bulk_email, _row(dmarc_policy="reject"), history))
    assert f.passed is True


async def test_d04_ignores_history_outside_the_thirty_day_window(
    bulk_email: ParsedEmail,
) -> None:
    # The window is 30 days. A reject policy from a year ago says nothing about
    # whether today's "none" is a change the sender just made.
    old = _rows(5, dmarc_policy="reject")
    for i, row in enumerate(old):
        row["received_at"] = (datetime.now(UTC) - timedelta(days=200 + i)).isoformat()
    f = _one(await d04_dmarc_policy_downgrade.run(bulk_email, _row(dmarc_policy="none"), old))
    assert _did_not_evaluate(f)


async def test_d04_reports_an_unrecognised_policy_rather_than_guessing(
    bulk_email: ParsedEmail,
) -> None:
    f = _one(
        await d04_dmarc_policy_downgrade.run(bulk_email, _row(dmarc_policy="banana"), _rows(5))
    )
    assert f.passed is True
    assert "banana" in f.message


# ── d08: unsubscribe affordances disappearing ──────────────────────────────


async def test_d08_quiet_when_the_headers_stay(bulk_email: ParsedEmail) -> None:
    f = _one(await d08_list_unsub_regression.run(bulk_email, _row(), _rows(5)))
    assert f.passed is True


async def test_d08_flags_a_dropped_one_click_header(bulk_email: ParsedEmail) -> None:
    # One-click unsubscribe is required of bulk senders by Gmail and Yahoo.
    # Losing it after having it is a compliance regression, not a style choice.
    current = _row(list_unsub_has_oneclick_post=0, list_unsub_has_https=0)
    f = _one(await d08_list_unsub_regression.run(bulk_email, current, _rows(10)))
    assert f.passed is False


# ── d10: display-name rotation ─────────────────────────────────────────────


async def test_d10_quiet_when_the_name_is_familiar(bulk_email: ParsedEmail) -> None:
    f = _one(await d10_display_name_rotation.run(bulk_email, _row(), _rows(10)))
    assert f.passed is True


async def test_d10_flags_a_name_never_seen_before(bulk_email: ParsedEmail) -> None:
    # 3 distinct names over 10 sends puts churn at exactly 0.3, which is not over
    # the 0.3 threshold, so only the new-name finding should fire.
    history = _rows(10)
    for i, row in enumerate(history):
        row["display_name"] = f"sender {i % 3}"
    current = _row(display_name="totally new sender")
    findings = await d10_display_name_rotation.run(bulk_email, current, history)
    failing = [f for f in findings if not f.passed]
    assert failing, "a never-before-seen name on a rotating sender must be reported"
    assert "totally new sender" in failing[0].message
    assert failing[0].severity == "MEDIUM"


async def test_d10_does_not_flag_a_single_rename_as_rotation(
    bulk_email: ParsedEmail,
) -> None:
    # A sender who always used one name and now uses another has rebranded. This
    # check reports rotation, so it must stay quiet rather than overclaim.
    current = _row(display_name="jane okafor partners")
    findings = await d10_display_name_rotation.run(bulk_email, current, _rows(10))
    assert all(f.passed for f in findings)


async def test_d10_flags_excessive_churn_on_its_own(bulk_email: ParsedEmail) -> None:
    # 8 distinct names across 10 sends is a rotating From, which is what
    # reputation-evasion tooling and shared sales inboxes look like.
    history = _rows(10)
    for i, row in enumerate(history):
        row["display_name"] = f"rep {i % 8}"
    findings = await d10_display_name_rotation.run(bulk_email, _row(display_name="rep 0"), history)
    churn = [f for f in findings if "churn" in f.message]
    assert churn, "8 names over 10 sends must be reported as churn"
    assert churn[0].severity == "HIGH"
    assert churn[0].passed is False


async def test_d10_needs_eight_rows_not_three(bulk_email: ParsedEmail) -> None:
    # A rotation claim needs a longer baseline than the other checks, so this one
    # sets its own threshold rather than using the shared default of 3.
    current = _row(display_name="totally new sender")
    f = _one(await d10_display_name_rotation.run(bulk_email, current, _rows(7)))
    assert _did_not_evaluate(f)


async def test_d10_flags_a_display_name_holding_a_foreign_domain(
    bulk_email: ParsedEmail,
) -> None:
    # "Support <billing@paypal.com>" sent from evil.net is the friendly-from
    # spoof. It fires with no history at all, because the mismatch is visible
    # in the single message.
    current = _row(display_name="billing@paypal.com", from_domain="evil.net")
    f = _one(await d10_display_name_rotation.run(bulk_email, current, []))
    assert f.passed is False
    assert f.severity == "HIGH"


async def test_d10_allows_a_display_name_holding_its_own_domain(
    bulk_email: ParsedEmail,
) -> None:
    # Some senders legitimately write the address in the display name. When the
    # embedded domain matches the sending domain there is nothing to spoof.
    current = _row(display_name="info@example.com", from_domain="example.com")
    findings = await d10_display_name_rotation.run(bulk_email, current, [])
    assert _one(findings).passed is True


# ── d11: Reply-To divergence ───────────────────────────────────────────────


async def test_d11_skips_mail_that_is_not_bulk() -> None:
    # Personal mail has a varied Reply-To by nature. Flagging it would make the
    # check fire on every reply thread.
    personal = parse_eml(b"From: a@example.com\r\nTo: b@example.com\r\nSubject: hi\r\n\r\nhello")
    f = _one(await d11_reply_to_divergence.run(personal, _row(), _rows(10)))
    assert f.passed is True
    assert "not bulk" in f.message


async def test_d11_quiet_when_reply_to_matches_from(bulk_email: ParsedEmail) -> None:
    f = _one(await d11_reply_to_divergence.run(bulk_email, _row(), _rows(10)))
    assert f.passed is True
    assert "aligned" in f.message


async def test_d11_flags_a_new_freemail_reply_to(bulk_email: ParsedEmail) -> None:
    # A bulk send that asks for replies at a Gmail address, when it never did
    # before, is the documented business-email-compromise pattern.
    current = _row(reply_to_domain="gmail.com")
    f = _one(await d11_reply_to_divergence.run(bulk_email, current, _rows(10)))
    assert f.passed is False
    assert f.severity == "CRITICAL"
    # The message has to name the free mailbox, because that is what separates
    # this from a plain new-domain change. It used to say "freemail", which is a
    # filter's word, not a reader's.
    assert "free personal mailbox" in f.message.lower()


async def test_d11_flags_a_new_corporate_reply_to_less_loudly(
    bulk_email: ParsedEmail,
) -> None:
    current = _row(reply_to_domain="some-agency.com")
    f = _one(await d11_reply_to_divergence.run(bulk_email, current, _rows(10)))
    assert f.passed is False
    assert "free personal mailbox" not in f.message.lower()


async def test_d11_accepts_a_reply_to_the_sender_has_used_before(
    bulk_email: ParsedEmail,
) -> None:
    history = _rows(10, reply_to_domain="gmail.com")
    f = _one(
        await d11_reply_to_divergence.run(bulk_email, _row(reply_to_domain="gmail.com"), history)
    )
    assert f.passed is True


async def test_d11_needs_three_rows_that_actually_carry_a_reply_to(
    bulk_email: ParsedEmail,
) -> None:
    # Rows with no Reply-To say nothing about which Reply-To is normal, so they
    # cannot count toward the baseline even though they count as history.
    history = _rows(10, reply_to_domain=None)
    f = _one(
        await d11_reply_to_divergence.run(bulk_email, _row(reply_to_domain="gmail.com"), history)
    )
    assert _did_not_evaluate(f)


async def test_d11_handles_history_where_only_some_rows_carry_a_reply_to(
    bulk_email: ParsedEmail,
) -> None:
    # A real store fills this field for some sends and not others. The rows
    # without it must be skipped, and the comparison must still run.
    history = [*_rows(5, reply_to_domain="example.com"), *_rows(5, reply_to_domain=None)]
    f = _one(
        await d11_reply_to_divergence.run(bulk_email, _row(reply_to_domain="gmail.com"), history)
    )
    assert f.passed is False
    assert "example.com" in str(f.details.get("prior", ""))


# ── the runner ─────────────────────────────────────────────────────────────


async def test_run_drift_returns_one_finding_per_check(bulk_email: ParsedEmail) -> None:
    findings = await run_drift(bulk_email, _rows(10))
    checks = {f.check for f in findings}
    assert len(checks) == 6, f"expected all 6 drift checks, saw {sorted(checks)}"


async def test_run_drift_on_empty_history_stays_quiet(bulk_email: ParsedEmail) -> None:
    findings = await run_drift(bulk_email, [])
    assert all(f.passed for f in findings), "no drift check may fail a sender with no history"
