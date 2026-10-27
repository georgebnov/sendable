"""The From display name: does it read as a person or as an organisation?

A recipient sorts mail by the From line before reading anything else. A personal
name clusters with one-to-one mail. An organisation name clusters with promotion.
The check reads the display name only, and reports LOW when it finds a collective
word, a legal-entity suffix, or a shared-inbox handle.

The token list carries no industry vocabulary. An earlier version flagged
`realty`, `properties`, and `homes`, which graded one trade and said nothing
about any other. The words that survive name a group or a legal entity in any
trade.
"""

from __future__ import annotations

import pytest

from engine.cleanup import cleanup
from engine.copywriting import personal_from_name
from engine.parse import ParsedEmail, parse_eml


def _email(from_addr: str) -> ParsedEmail:
    raw = (
        f"From: {from_addr}\r\n"
        "To: sam@example.net\r\n"
        "Subject: Office hours Saturday\r\n"
        "\r\nHello.\r\n"
    ).encode()
    return parse_eml(raw)


async def _run(from_addr: str):
    findings = await personal_from_name.run(_email(from_addr))
    assert len(findings) == 1
    return findings[0]


@pytest.mark.parametrize(
    "display",
    ["Jane Okafor", "Jane", "Jane Okafor Müller", "J. Okafor"],
)
async def test_a_personal_name_passes(display: str) -> None:
    f = await _run(f"{display} <jane@example.com>")
    assert f.passed, f.message


@pytest.mark.parametrize(
    "token",
    ["Team", "Group", "Associates", "Partners", "Inc", "LLC", "Ltd", "Corp", "PLC", "GmbH"],
)
async def test_a_collective_or_legal_entity_token_fires(token: str) -> None:
    f = await _run(f"Okafor {token} <jane@example.com>")
    assert not f.passed
    assert token.lower() in f.details["matches"]


async def test_a_trailing_co_dot_fires() -> None:
    # `co.` carries a literal dot, so it needs its own pattern rather than a
    # word boundary. Without it "Okafor Co." read as a personal name.
    f = await _run("Okafor Co. <jane@example.com>")
    assert not f.passed
    assert "co." in f.details["matches"]


@pytest.mark.parametrize("handle", ["info", "support", "noreply", "no-reply"])
async def test_a_shared_inbox_handle_fires(handle: str) -> None:
    f = await _run(f"{handle} <{handle}@example.com>")
    assert not f.passed
    assert f"handle:{handle}" in f.details["matches"]


@pytest.mark.parametrize("display", ["Okafor Realty", "Okafor Properties", "Dream Homes"])
async def test_industry_vocabulary_no_longer_fires(display: str) -> None:
    # These three words graded one trade. A supplier called "Okafor Properties"
    # is an organisation, but so is every name the surviving tokens already
    # catch, and these three carry no signal outside that trade.
    f = await _run(f"{display} <jane@example.com>")
    assert f.passed, f.message


async def test_a_first_name_merge_tag_passes() -> None:
    # The tag is a personal-name slot. A real first name lands there at send time.
    f = await _run("{{first_name}} <jane@example.com>")
    assert f.passed
    assert f.details["placeholders"] == ["{{first_name}}"]


async def test_a_non_name_merge_tag_fires() -> None:
    f = await _run("{{company_name}} <jane@example.com>")
    assert not f.passed
    assert f.details["placeholders"] == ["{{company_name}}"]


async def test_no_display_name_passes() -> None:
    # The recipient sees the raw address. There is no display name to grade.
    f = await _run("jane@example.com")
    assert f.passed


async def test_the_substituted_company_name_still_fires() -> None:
    """A test send can put a company field in the From line.

    Cleanup fills an unsubstituted merge tag with a fake value before any check
    runs, so the value it picks decides what this check sees. A fake value that
    reads as a personal name makes the check pass on a send that should fail it,
    and nothing else in the suite would notice.
    """
    raw = (
        b"From: {{company_name}} <jane@example.com>\r\n"
        b"To: sam@example.net\r\n"
        b"Subject: [TEST] Office hours Saturday\r\n"
        b"\r\nHello.\r\n"
    )
    cleaned, _ = cleanup(parse_eml(raw))
    findings = await personal_from_name.run(cleaned)
    assert len(findings) == 1
    assert not findings[0].passed, f"substituted {cleaned.from_addr!r} read as personal"
