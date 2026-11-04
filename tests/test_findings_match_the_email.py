"""Three findings that said something the email in front of them did not support.

Each one came from a real audit of a promotional email, and each test below is
built from the state that produced the false statement.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

from engine import runner
from engine.copywriting import from_name_body_consistency
from engine.domain.integrity import unsubscribe
from engine.parse import ParsedEmail, parse_eml
from engine.report import Finding, Report
from engine.runner import audit
from engine.scoring import score_findings

ROOT = pathlib.Path(__file__).resolve().parent.parent

_ONE_CLICK = b"List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n"
_UNSUB_HEADER = b"List-Unsubscribe: <https://example.com/u>\r\n"


def _bulk(headers: bytes) -> bytes:
    return (
        b"From: Acme <news@example.com>\r\n"
        b"To: reader@example.com\r\n"
        b"Subject: Fall sale\r\n"
        b"Precedence: bulk\r\n" + headers + b"Content-Type: text/plain\r\n\r\nHello.\r\n"
    )


async def _post_finding(raw: bytes) -> Finding:
    findings = await unsubscribe.run(parse_eml(raw))
    return next(f for f in findings if f.check == "content.list_unsubscribe_post")


# ── content.list_unsubscribe_post ──────────────────────────────────────────


async def test_mail_with_no_unsubscribe_is_not_told_its_link_works() -> None:
    finding = await _post_finding(_bulk(b""))
    assert not finding.passed
    assert "works" not in finding.message
    assert "no one-click unsubscribe" in finding.message


async def test_mail_with_the_header_only_is_told_the_one_click_form_is_missing() -> None:
    finding = await _post_finding(_bulk(_UNSUB_HEADER))
    assert not finding.passed
    assert "cannot leave in one click" in finding.message
    # The header being there says nothing about whether its address responds.
    assert "works" not in finding.message


async def test_the_one_click_marker_alone_is_not_one_click_unsubscribe() -> None:
    # The marker tells a mail app to post to the unsubscribe address. With no
    # address, there is nothing to post to, so a reader still cannot leave.
    finding = await _post_finding(_bulk(_ONE_CLICK))
    assert not finding.passed


async def test_the_marker_and_the_address_together_pass() -> None:
    finding = await _post_finding(_bulk(_UNSUB_HEADER + _ONE_CLICK))
    assert finding.passed


# ── copywriting.from_name_body_consistency ─────────────────────────────────


def _signed(from_name: bytes, plain: bytes) -> bytes:
    return (
        b"From: " + from_name + b" <news@example.com>\r\n"
        b"To: reader@example.com\r\n"
        b"Subject: Fall sale\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n" + plain
    )


async def _name_finding(raw: bytes) -> Finding:
    (finding,) = await from_name_body_consistency.run(parse_eml(raw))
    return finding


_BODY = b"Every jacket in the store is half price until Sunday night.\r\n\r\n"


@pytest.mark.parametrize(
    "closing",
    [
        # The name and the address share a paragraph, so the paragraph is a footer.
        pytest.param(
            b"Alder & Pine Outfitters\r\n12 Harbour Road, Halifax\r\n",
            id="name-on-the-address-line",
        ),
        # The sign-off word is the signature, and the name went with the address.
        pytest.param(
            b"Thanks,\r\n\r\nAlder & Pine Outfitters\r\n12 Harbour Road, Halifax\r\n",
            id="sign-off-word-then-address",
        ),
        # A P.S. used to replace the rest of the closing.
        pytest.param(
            b"Alder & Pine Outfitters\r\n\r\nP.S. The coats go first.\r\n",
            id="name-before-a-ps",
        ),
    ],
)
async def test_the_from_name_counts_anywhere_in_the_closing(closing: bytes) -> None:
    finding = await _name_finding(_signed(b"Alder & Pine Outfitters", _BODY + closing))
    assert finding.passed, finding.details


async def test_an_entity_in_the_html_closing_is_read_as_the_character() -> None:
    raw = (
        b"From: Alder & Pine Outfitters <news@example.com>\r\n"
        b"To: reader@example.com\r\n"
        b"Subject: Fall sale\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n"
        b"<p>Every jacket is half price.</p><p>Alder &amp; Pine Outfitters</p>\r\n"
    )
    finding = await _name_finding(raw)
    assert finding.details["match_kind"] == "full"


async def test_a_closing_that_names_someone_else_still_fails() -> None:
    closing = b"Thanks,\r\n\r\nBob Smith\r\n\r\nNorthwind Ltd\r\n12 Harbour Road, Halifax\r\n"
    finding = await _name_finding(_signed(b"Jane Okafor", _BODY + closing))
    assert not finding.passed


async def test_a_name_early_in_a_long_body_is_not_in_the_closing() -> None:
    plain = b"Jane Okafor wrote to us. " + b"Every jacket is half price. " * 20 + b"\r\n"
    finding = await _name_finding(_signed(b"Jane Okafor", plain))
    assert not finding.passed


# ── --offline ──────────────────────────────────────────────────────────────

_OFFLINE_ADVISORY = "sender.offline_mode"


async def _offline_report() -> Report:
    return await audit(parse_eml(_bulk(_UNSUB_HEADER + _ONE_CLICK)), domain_health=False)


async def test_an_offline_report_names_the_sub_scores_it_did_not_verify() -> None:
    report = await _offline_report()
    advisory = next(f for f in report.findings if f.check == _OFFLINE_ADVISORY)
    assert advisory.details["unverified_sub_scores"] == ["domain_records", "infrastructure"]
    assert "not because they passed" in advisory.message


async def test_the_offline_advisory_does_not_change_the_score() -> None:
    report = await _offline_report()
    advisory = next(f for f in report.findings if f.check == _OFFLINE_ADVISORY)
    others = [f for f in report.findings if f is not advisory]
    assert score_findings(report.findings) == score_findings(others)


async def test_a_full_run_has_no_offline_advisory(monkeypatch: pytest.MonkeyPatch) -> None:
    async def no_findings(_email: ParsedEmail) -> list[Finding]:
        return []

    monkeypatch.setattr(runner, "run_domain_health", no_findings)
    report = await audit(parse_eml(_bulk(_UNSUB_HEADER + _ONE_CLICK)), domain_health=True)
    assert _OFFLINE_ADVISORY not in [f.check for f in report.findings]


def test_the_command_line_says_the_network_checks_were_skipped() -> None:
    out = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "audit.py"),
            str(ROOT / "tests" / "fixtures" / "broken_bulk.eml"),
            "--offline",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=True,
    )
    assert "[offline]" in out.stderr
    checks = [f["check"] for f in json.loads(out.stdout)["findings"]]
    assert _OFFLINE_ADVISORY in checks
