"""The blocklist fan-out: is this sender's IP or links listed anywhere.

A blocklist, or RBL, answers a DNS query about a reversed IP. An A record in
127.0.0.0/8 means listed. Several lists return a sentinel address to say "query
refused" or "rate limited", and reading that as a listing would tell a clean sender
they are blocked, so sentinels are filtered out. Hostkarma also answers about
senders it does not list, so only its black code means listed.

NXDOMAIN means not listed only when the list also passed its test name in the same
audit. Every list keeps a test name that must always read as listed. Spamhaus
answers NXDOMAIN for that name through some public resolvers, so without the test a
listed sender reads as clean. A failed test leaves the list not checked.

These checks are why `--offline` exists: they query 22 IP blocklists and 6 URL
blocklists, and the test name of each one.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from engine.domain.dns import blacklist, sender_dbl, sending_ip_dns, url_reputation
from engine.parse import parse_eml
from engine.report import Finding
from engine.scoring import score_findings
from tests.conftest import FakeDns

ROOT = pathlib.Path(__file__).parent.parent
_DOCS_WITH_THE_COUNT = ("README.md", "SECURITY.md", "SKILL.md", "references/CHECKS.md")
_IP_LIST_COUNT = re.compile(r"\b(\d+)\s+IP\s+(?:RBL\s+lists|blocklists)\b")
_URL_LIST_COUNT = re.compile(
    r"\b(\d+)\s+(?:URL\s+blocklists|domain\s+(?:DBLs|blocklists)"
    r"|DBLs\s+per\s+body\s+link|blocklists\s+against\s+every\s+link)\b"
)
_ROW = re.compile(r"\| `([^`]+)` \| `([^`]+)` \| (HIGH|MEDIUM|LOW) \|")


# 34.216.184.93 is the reversed form of 93.184.216.34, which is how every blocklist
# is queried.
_HEADERS = {"received": ["from mail.example.com (mail.example.com [93.184.216.34]) by mx"]}
_REVERSED = "34.216.184.93"
# What each operator answered as listed on 2026-11-04. `test.<list>` is NXDOMAIN on
# the two Spam Eating Monkey lists.
_DOMAIN_TEST_NAMES = {
    "multi.uribl.com": "test.uribl.com.multi.uribl.com",
    "uribl.spameatingmonkey.net": "test.spameatingmonkey.net.uribl.spameatingmonkey.net",
    "urired.spameatingmonkey.net": "test.spameatingmonkey.net.urired.spameatingmonkey.net",
}


def _failing(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if not f.passed]


def _ip_test_name(host: str) -> str:
    return f"2.0.0.127.{host}"


def _domain_test_name(host: str) -> str:
    return _DOMAIN_TEST_NAMES.get(host, f"test.{host}")


def _pass_ip_tests(dns: FakeDns) -> None:
    """Make every IP list answer its test address, the way a working network does."""
    for _, host, _, _ in blacklist._RBLS:
        dns.set(_ip_test_name(host), "A", "127.0.0.2")


def _pass_domain_tests(dns: FakeDns) -> None:
    for _, host, _, _ in url_reputation._DBLS:
        dns.set(_domain_test_name(host), "A", "127.0.0.2")


def _one(findings: list[Finding], check: str) -> Finding:
    matches = [f for f in findings if f.check == check]
    assert len(matches) == 1, f"expected 1 {check}, found {len(matches)}"
    return matches[0]


def _link_email(*domains: str) -> bytes:
    links = "".join(f'<a href="https://{d}/x">Read</a>' for d in domains)
    html = f"<html><body>{links}</body></html>"
    head = "From: Jane <jane@example.com>\r\nContent-Type: text/html\r\n\r\n"
    return (head + html).encode()


# ── finding the sending IP ─────────────────────────────────────────────────


def test_the_sending_ip_comes_from_the_received_chain() -> None:
    headers = {
        "received": [
            "from mail.example.com (mail.example.com [93.184.216.34]) by mx.google.com",
            "from internal (internal [10.0.0.1]) by mail.example.com",
        ]
    }
    assert blacklist.extract_sender_ip(headers) == "93.184.216.34"


def test_a_private_address_is_not_taken_as_the_sending_ip() -> None:
    # The oldest hop is often inside the sender's own network. Querying a
    # blocklist about 10.0.0.1 answers nothing useful.
    headers = {"received": ["from internal (internal [10.0.0.1]) by mail.example.com"]}
    assert blacklist.extract_sender_ip(headers) is None


def test_no_received_chain_yields_no_ip() -> None:
    assert blacklist.extract_sender_ip({}) is None


# ── the IP blocklist fan-out ───────────────────────────────────────────────


async def test_an_unlisted_ip_passes_every_list(dns: FakeDns) -> None:
    # Every list passes its test address, and the sender answers NXDOMAIN on each.
    # NXDOMAIN alone proves nothing: see the tests below that leave the test out.
    _pass_ip_tests(dns)
    findings = await blacklist.run(_HEADERS)
    assert findings
    assert not _failing(findings)


async def test_a_listed_ip_is_reported(dns: FakeDns) -> None:
    # 34.216.184.93 is the reversed form of 93.184.216.34, which is how every
    # blocklist is queried.
    dns.set("34.216.184.93.zen.spamhaus.org", "A", "127.0.0.2")
    headers = {"received": ["from mail.example.com (mail.example.com [93.184.216.34]) by mx"]}
    failing = _failing(await blacklist.run(headers))
    assert failing, "a listing on Spamhaus ZEN must be reported"
    assert any("spamhaus" in f.check for f in failing)


async def test_a_sentinel_response_is_not_read_as_a_listing(dns: FakeDns) -> None:
    # Several lists answer 127.255.255.254 to mean "query refused" or "rate
    # limited", which a residential connection hits often. Reading that as a
    # listing would tell a clean sender they are blocked.
    _pass_ip_tests(dns)
    dns.set(f"{_REVERSED}.zen.spamhaus.org", "A", "127.255.255.254")
    findings = await blacklist.run(_HEADERS)
    assert not [f for f in findings if f.check == "blacklist.spamhaus_zen"]
    # Reported as not checked rather than as a listing: INFO carries no penalty.
    # "We could not check" and "we checked and it is clean" differ.
    unverified = _one(findings, "blacklist.unverified")
    assert unverified.severity == "INFO"
    assert unverified.details["lists"] == ["zen.spamhaus.org"]


async def test_no_sending_ip_skips_the_fan_out(dns: FakeDns) -> None:
    # It says so rather than staying silent, because "we could not check" and
    # "we checked and it is clean" are different answers. INFO carries no penalty.
    findings = await blacklist.run({})
    assert findings
    assert all(f.severity == "INFO" for f in findings)
    assert len(dns.asked) == 0, "no IP means there is nothing to ask about"


async def test_a_message_sent_over_ipv6_is_not_told_to_audit_the_arrived_copy(
    dns: FakeDns,
) -> None:
    # This copy did arrive, and its address is in the chain. Only an IPv4 address
    # can go to these lists, so "it shows no address" sends the user in a circle.
    headers = {"received": ["from mail.example.com ([2001:db8::25]) by mx"]}
    message = _one(await blacklist.run(headers), "blacklist.sender_ip_extraction").message
    assert "IPv6" in message
    assert "draft" in message


async def test_a_not_checked_list_keeps_the_answer_it_gave(dns: FakeDns) -> None:
    # A refusal, a timeout, and a failed test each need a different next step, so the
    # answer stays in the finding. The per list rows used to carry it.
    _pass_ip_tests(dns)
    dns.set(f"{_REVERSED}.zen.spamhaus.org", "A", "127.255.255.254")
    dns.fail(f"{_REVERSED}.bl.spamcop.net", "A", "timeout")
    unchecked = _one(await blacklist.run(_HEADERS), "blacklist.unverified").details["unchecked"]
    assert unchecked == [
        {"list": "zen.spamhaus.org", "name": "93.184.216.34", "answer": "127.255.255.254"},
        {"list": "bl.spamcop.net", "name": "93.184.216.34", "answer": "timeout"},
    ]


# ── the test address of each list ──────────────────────────────────────────


async def test_nxdomain_on_the_test_address_is_not_clean(dns: FakeDns) -> None:
    # The real defect. Through 8.8.8.8, zen.spamhaus.org answered NXDOMAIN for
    # 2.0.0.127, the address it must always list. The same answer about a sender
    # means nothing, so a listed sender read as "Not listed on spamhaus_zen".
    _pass_ip_tests(dns)
    dns.fail(_ip_test_name("zen.spamhaus.org"), "A", "nxdomain")
    findings = await blacklist.run(_HEADERS)
    assert not [f for f in findings if f.check == "blacklist.spamhaus_zen"]
    assert _one(findings, "blacklist.unverified").details["lists"] == ["zen.spamhaus.org"]


async def test_a_refusal_on_the_test_address_is_not_clean(dns: FakeDns) -> None:
    _pass_ip_tests(dns)
    dns.set(_ip_test_name("zen.spamhaus.org"), "A", "127.255.255.254")
    findings = await blacklist.run(_HEADERS)
    assert not [f for f in findings if f.check == "blacklist.spamhaus_zen"]
    assert _one(findings, "blacklist.unverified").details["lists"] == ["zen.spamhaus.org"]


async def test_a_passed_test_address_and_a_clean_sender_is_clean(dns: FakeDns) -> None:
    _pass_ip_tests(dns)
    finding = _one(await blacklist.run(_HEADERS), "blacklist.spamhaus_zen")
    assert finding.passed
    assert finding.message == "Not listed on spamhaus_zen."


async def test_a_passed_test_address_and_a_listed_sender_is_listed(dns: FakeDns) -> None:
    _pass_ip_tests(dns)
    dns.set(f"{_REVERSED}.zen.spamhaus.org", "A", "127.0.0.2")
    finding = _one(await blacklist.run(_HEADERS), "blacklist.spamhaus_zen")
    assert not finding.passed
    assert finding.severity == "HIGH"
    assert finding.details["test_passed"] is True


async def test_a_listing_stands_when_the_test_address_fails(dns: FakeDns) -> None:
    # Some lists skip the test address. A listed answer about the sender is still
    # evidence, and dropping it would hide a real listing.
    dns.set(f"{_REVERSED}.bl.nordspam.com", "A", "127.0.0.2")
    finding = _one(await blacklist.run(_HEADERS), "blacklist.nordspam_bl")
    assert not finding.passed
    assert finding.severity == "MEDIUM"
    assert finding.details["test_passed"] is False


@pytest.mark.parametrize("error", ["no_answer", "timeout", "servfail"])
async def test_no_usable_sender_answer_is_not_clean(dns: FakeDns, error: str) -> None:
    # A filter on the network can remove the answer: NOERROR with 0 records.
    _pass_ip_tests(dns)
    dns.fail(f"{_REVERSED}.bl.spamcop.net", "A", error)
    findings = await blacklist.run(_HEADERS)
    assert not [f for f in findings if f.check == "blacklist.spamcop"]
    assert _one(findings, "blacklist.unverified").details["lists"] == ["bl.spamcop.net"]


@pytest.mark.parametrize(
    ("host", "answers"),
    [
        # What each operator answered for its test address on 2026-11-04.
        ("dnsbl.dronebl.org", ("127.0.0.1",)),
        ("torexit.dan.me.uk", ("127.0.0.100",)),
        ("bl.mailspike.net", ("127.0.0.2", "127.0.0.10", "127.0.0.11", "127.0.0.13")),
        (
            "hostkarma.junkemailfilter.com",
            (
                "127.0.0.1",
                "127.0.0.2",
                "127.0.0.3",
                "127.0.0.4",
                "127.0.0.5",
                "127.0.1.1",
                "127.0.1.2",
                "127.0.1.3",
            ),
        ),
    ],
)
async def test_each_operator_test_answer_passes(
    dns: FakeDns, host: str, answers: tuple[str, ...]
) -> None:
    _pass_ip_tests(dns)
    dns.set(_ip_test_name(host), "A", *answers)
    findings = await blacklist.run(_HEADERS)
    assert not [f for f in findings if f.check == "blacklist.unverified"]


async def test_loopback_passes_the_test_only_for_dronebl(dns: FakeDns) -> None:
    # 127.0.0.1 is a refusal on most lists. DroneBL alone uses it as a test answer.
    _pass_ip_tests(dns)
    dns.set(_ip_test_name("bl.spamcop.net"), "A", "127.0.0.1")
    findings = await blacklist.run(_HEADERS)
    assert _one(findings, "blacklist.unverified").details["lists"] == ["bl.spamcop.net"]


async def test_loopback_about_a_sender_is_not_a_listing_on_dronebl(dns: FakeDns) -> None:
    _pass_ip_tests(dns)
    dns.set(_ip_test_name("dnsbl.dronebl.org"), "A", "127.0.0.1")
    dns.set(f"{_REVERSED}.dnsbl.dronebl.org", "A", "127.0.0.1")
    findings = await blacklist.run(_HEADERS)
    assert not [f for f in findings if f.check == "blacklist.dronebl"]
    assert _one(findings, "blacklist.unverified").details["lists"] == ["dnsbl.dronebl.org"]


# ── a list whose codes say more than "listed" ──────────────────────────────

_HOSTKARMA = "hostkarma.junkemailfilter.com"


@pytest.mark.parametrize(
    "answers",
    [
        # What real senders got on 2026-11-04. Each one read as a listing.
        ("127.0.0.5",),  # Gmail, 209.85.220.41: must not be blacklisted
        ("127.0.0.3", "127.0.1.1"),  # Amazon SES, 54.240.27.11: mixed mail
        ("127.0.0.1", "127.0.1.1"),  # Mailchimp, 205.201.128.1: trusted
        # The other documented codes.
        ("127.0.0.1",),  # white: this one read as not checked
        ("127.0.0.3",),  # yellow
        ("127.0.0.4",),  # brown: "all spam - but not yet enough to blacklist"
        ("127.0.1.2",),  # the sender does not use QUIT
        ("127.0.1.3", "127.0.2.1"),  # mixed QUIT, a new domain
    ],
)
async def test_a_hostkarma_code_that_is_not_black_is_clean(
    dns: FakeDns, answers: tuple[str, ...]
) -> None:
    _pass_ip_tests(dns)
    dns.set(f"{_REVERSED}.{_HOSTKARMA}", "A", *answers)
    findings = await blacklist.run(_HEADERS)
    assert _one(findings, "blacklist.hostkarma_black").passed
    assert not [f for f in findings if f.check == "blacklist.unverified"]


@pytest.mark.parametrize("answers", [("127.0.0.2",), ("127.0.0.2", "127.0.1.2")])
async def test_the_hostkarma_black_code_is_a_listing(
    dns: FakeDns, answers: tuple[str, ...]
) -> None:
    _pass_ip_tests(dns)
    dns.set(f"{_REVERSED}.{_HOSTKARMA}", "A", *answers)
    finding = _one(await blacklist.run(_HEADERS), "blacklist.hostkarma_black")
    assert not finding.passed
    assert finding.severity == "MEDIUM"


async def test_the_hostkarma_test_needs_the_black_code(dns: FakeDns) -> None:
    # Yellow and white are clean only after a test that proved the black code arrives.
    _pass_ip_tests(dns)
    dns.set(_ip_test_name(_HOSTKARMA), "A", "127.0.0.1", "127.0.0.3")
    dns.set(f"{_REVERSED}.{_HOSTKARMA}", "A", "127.0.0.3")
    findings = await blacklist.run(_HEADERS)
    assert not [f for f in findings if f.check == "blacklist.hostkarma_black"]
    assert _one(findings, "blacklist.unverified").details["lists"] == [_HOSTKARMA]


@pytest.mark.parametrize(
    "answers",
    [
        ("127.255.255.254",),  # a refusal is not a code of this list
        ("198.51.100.7",),
        ("127.0.0.3", "198.51.100.7"),  # 1 foreign record spoils the answer
        ("127.0.0.6",),  # the operator documents no such code, so it proves nothing
        ("127.0.3.1",),
        ("127.0.0.3", "127.0.0.6"),  # 1 unknown code spoils the answer
    ],
)
async def test_a_hostkarma_answer_with_a_foreign_record_is_not_checked(
    dns: FakeDns, answers: tuple[str, ...]
) -> None:
    _pass_ip_tests(dns)
    dns.set(f"{_REVERSED}.{_HOSTKARMA}", "A", *answers)
    findings = await blacklist.run(_HEADERS)
    assert not [f for f in findings if f.check == "blacklist.hostkarma_black"]
    assert _one(findings, "blacklist.unverified").details["lists"] == [_HOSTKARMA]


async def test_no_records_from_hostkarma_is_not_clean(dns: FakeDns) -> None:
    _pass_ip_tests(dns)
    dns.fail(f"{_REVERSED}.{_HOSTKARMA}", "A", "no_answer")
    findings = await blacklist.run(_HEADERS)
    assert _one(findings, "blacklist.unverified").details["lists"] == [_HOSTKARMA]


async def test_the_hostkarma_codes_apply_to_hostkarma_alone(dns: FakeDns) -> None:
    # Another list has no white or yellow code, so 127.0.1.1 stays a listing there.
    _pass_ip_tests(dns)
    dns.set(f"{_REVERSED}.bl.spamcop.net", "A", "127.0.1.1")
    assert not _one(await blacklist.run(_HEADERS), "blacklist.spamcop").passed


@pytest.mark.parametrize(
    "answer",
    [
        "198.51.100.7",  # a parked domain or a resolver that rewrites NXDOMAIN
        "127.255.255.1",  # the refusal range holds more than the 3 named codes
        "not-an-address",
    ],
)
async def test_an_answer_outside_the_listing_range_is_not_a_listing(
    dns: FakeDns, answer: str
) -> None:
    _pass_ip_tests(dns)
    dns.set(f"{_REVERSED}.zen.spamhaus.org", "A", answer)
    findings = await blacklist.run(_HEADERS)
    assert not [f for f in findings if f.check == "blacklist.spamhaus_zen"]
    assert _one(findings, "blacklist.unverified").details["lists"] == ["zen.spamhaus.org"]


async def test_a_failed_test_address_gives_one_plain_finding(dns: FakeDns) -> None:
    # Nothing registered: all 22 test addresses fail, as on a filtering network.
    findings = await blacklist.run(_HEADERS)
    assert len(_failing(findings)) == 1, "22 lists must not become 22 rows"
    finding = _one(findings, "blacklist.unverified")
    assert finding.severity == "INFO"
    assert len(finding.details["lists"]) == len(blacklist._RBLS)
    message = finding.message
    assert "22 of 22" in message
    assert "not as clean" in message
    # Rule 9: it says what to do next. Rule 12: in words a marketer uses.
    assert "another network" in message
    assert not re.search(r"sentinel|resolver|\bRBL\b|DNS|NXDOMAIN|\u2014|\u2013", message)


async def test_not_checked_lists_neither_lift_nor_cut_the_score(dns: FakeDns) -> None:
    # A not checked list takes the existing inconclusive path: INFO, 0 penalty.
    # It must not read as a listing, and no hard gate may fire.
    _pass_ip_tests(dns)
    clean = score_findings(await blacklist.run(_HEADERS))
    dns.fail(_ip_test_name("zen.spamhaus.org"), "A", "nxdomain")
    dns.fail(_ip_test_name("bl.spamcop.net"), "A", "timeout")
    from_a_failed_test = score_findings(await blacklist.run(_HEADERS))
    assert from_a_failed_test["score"] == clean["score"]
    assert from_a_failed_test["hard_gates_failed"] == []


@pytest.mark.parametrize("failure", ["nxdomain", "no_answer", "timeout", "servfail"])
async def test_guard_no_list_is_clean_without_a_passed_test(dns: FakeDns, failure: str) -> None:
    # Walks _RBLS, so a list added later is under the guard at once.
    for _, host, _, _ in blacklist._RBLS:
        dns.fail(_ip_test_name(host), "A", failure)
    findings = await blacklist.run(_HEADERS)
    labels = {f"blacklist.{label}" for label, _, _, _ in blacklist._RBLS}
    clean = sorted(f.check for f in findings if f.check in labels and f.passed)
    assert not clean, (
        f"{clean} passed with a failed test address. In engine/domain/dns/blacklist.py, "
        "send each sender answer through read_answer with the result of the test."
    )


def test_guard_only_the_reading_module_interprets_nxdomain() -> None:
    # NXDOMAIN reads as clean only after a passed test, and read_answer alone
    # knows both facts. A list module that tests for it again brings the bug back.
    modules = ("blacklist.py", "sender_dbl.py", "url_reputation.py")
    source = ROOT / "engine" / "domain" / "dns"
    offenders = [name for name in modules if '"nxdomain"' in (source / name).read_text()]
    assert not offenders, (
        f"{offenders} under engine/domain/dns read NXDOMAIN directly. "
        "Call read_answer from engine/domain/dns/list_reading.py instead."
    )


# ── the URL blocklists ─────────────────────────────────────────────────────


async def test_a_clean_link_domain_passes(dns: FakeDns) -> None:
    email = parse_eml(
        b"From: Jane <jane@example.com>\r\nContent-Type: text/html\r\n\r\n"
        b'<html><body><a href="https://example.com/x">Read</a></body></html>'
    )
    assert not _failing(await url_reputation.run(email, "example.com"))


async def test_a_listed_link_domain_is_reported(dns: FakeDns) -> None:
    dns.set("bad.test.dbl.spamhaus.org", "A", "127.0.1.2")
    email = parse_eml(
        b"From: Jane <jane@example.com>\r\nContent-Type: text/html\r\n\r\n"
        b'<html><body><a href="https://bad.test/x">Read</a></body></html>'
    )
    failing = _failing(await url_reputation.run(email, "example.com"))
    assert failing, "a link to a listed domain must be reported"


async def test_an_email_with_no_links_is_not_graded(dns: FakeDns) -> None:
    email = parse_eml(b"From: Jane <jane@example.com>\r\n\r\nNo links here.\r\n")
    findings = await url_reputation.run(email, "example.com")
    assert findings
    assert not _failing(findings)
    assert len(dns.asked) == 0, "no link means no list needs a test"


async def test_a_link_is_clean_only_after_the_list_passed_its_test(dns: FakeDns) -> None:
    email = parse_eml(_link_email("clean.test"))
    _pass_domain_tests(dns)
    findings = await url_reputation.run(email, "example.com")
    assert not _failing(findings)
    assert _one(findings, "url_reputation.no_listings").passed


async def test_a_failed_list_test_means_links_are_not_checked(dns: FakeDns) -> None:
    email = parse_eml(_link_email("clean.test"))
    findings = await url_reputation.run(email, "example.com")
    assert not [f for f in findings if f.check == "url_reputation.no_listings"]
    finding = _one(findings, "url_reputation.unverified")
    assert finding.severity == "INFO"
    assert len(finding.details["lists"]) == len(url_reputation._DBLS)


async def test_one_failed_link_lookup_stops_the_clean_summary(dns: FakeDns) -> None:
    # Every test passed, and 1 of 2 domains timed out on 1 list. That is not clean.
    email = parse_eml(_link_email("one.test", "two.test"))
    _pass_domain_tests(dns)
    dns.fail("two.test.dbl.spamhaus.org", "A", "timeout")
    findings = await url_reputation.run(email, "example.com")
    assert not [f for f in findings if f.check == "url_reputation.no_listings"]
    assert _one(findings, "url_reputation.unverified").details["lists"] == ["dbl.spamhaus.org"]


async def test_a_hit_and_a_not_checked_list_are_both_reported(dns: FakeDns) -> None:
    email = parse_eml(_link_email("bad.test"))
    dns.set("bad.test.dbl.spamhaus.org", "A", "127.0.1.2")
    findings = await url_reputation.run(email, "example.com")
    assert _one(findings, "url_reputation.spamhaus_dbl").details["test_passed"] is False
    assert "dbl.spamhaus.org" not in _one(findings, "url_reputation.unverified").details["lists"]


async def test_each_list_is_tested_once_however_many_links(dns: FakeDns) -> None:
    email = parse_eml(_link_email("one.test", "two.test", "three.test"))
    await url_reputation.run(email, "example.com")
    asked = [name for _, name in dns.asked if name.startswith("test.dbl.spamhaus")]
    assert asked == ["test.dbl.spamhaus.org"]


async def test_the_uribl_refusal_does_not_pass_its_test(dns: FakeDns) -> None:
    # URIBL answers 127.0.0.1 to a public resolver, about every name.
    email = parse_eml(_link_email("clean.test"))
    _pass_domain_tests(dns)
    dns.set(_domain_test_name("multi.uribl.com"), "A", "127.0.0.1")
    dns.set("clean.test.multi.uribl.com", "A", "127.0.0.1")
    findings = await url_reputation.run(email, "example.com")
    assert _one(findings, "url_reputation.unverified").details["lists"] == ["multi.uribl.com"]


async def test_the_not_checked_finding_names_the_link_domain(dns: FakeDns) -> None:
    # 1 of 2 domains timed out. The other one was checked, so the finding has to say
    # which is which.
    email = parse_eml(_link_email("one.test", "two.test"))
    _pass_domain_tests(dns)
    dns.fail("two.test.dbl.spamhaus.org", "A", "timeout")
    finding = _one(await url_reputation.run(email, "example.com"), "url_reputation.unverified")
    assert finding.details["unchecked"] == [
        {"list": "dbl.spamhaus.org", "name": "two.test", "answer": "timeout"}
    ]


async def test_the_scanned_row_counts_only_the_lists_that_answered(dns: FakeDns) -> None:
    # This row passes, so a full count would read as full coverage.
    email = parse_eml(_link_email("one.test", "two.test"))
    _pass_domain_tests(dns)
    dns.fail("one.test.dbl.spamhaus.org", "A", "timeout")
    dns.fail("two.test.dbl.spamhaus.org", "A", "timeout")
    scanned = _one(await url_reputation.run(email, "example.com"), "url_reputation.scanned")
    assert "5 of 6" in scanned.message


# ── the sender domain on a domain blocklist ────────────────────────────────


async def test_an_unlisted_sender_domain_passes(dns: FakeDns) -> None:
    _pass_domain_tests(dns)
    findings = await sender_dbl.run("example.com")
    assert not _failing(findings)
    assert _one(findings, "sender_dbl.no_listings").passed


async def test_a_listed_sender_domain_is_reported(dns: FakeDns) -> None:
    dns.set("example.com.dbl.spamhaus.org", "A", "127.0.1.2")
    finding = _one(await sender_dbl.run("example.com"), "sender_dbl.spamhaus_dbl")
    assert finding.severity == "CRITICAL"
    assert finding.hard_gate


@pytest.mark.parametrize("failure", ["nxdomain", "no_answer", "timeout"])
async def test_a_failed_list_test_leaves_the_sender_domain_unchecked(
    dns: FakeDns, failure: str
) -> None:
    for _, host, _, _ in url_reputation._DBLS:
        dns.fail(_domain_test_name(host), "A", failure)
    findings = await sender_dbl.run("example.com")
    assert not [f for f in findings if f.check == "sender_dbl.no_listings"]
    finding = _one(findings, "sender_dbl.unverified")
    assert finding.severity == "INFO"
    assert not finding.hard_gate
    assert finding.source == "domain_config"


async def test_a_failed_sender_lookup_stops_the_clean_summary(dns: FakeDns) -> None:
    _pass_domain_tests(dns)
    dns.fail("example.com.multi.surbl.org", "A", "timeout")
    findings = await sender_dbl.run("example.com")
    assert not [f for f in findings if f.check == "sender_dbl.no_listings"]
    assert _one(findings, "sender_dbl.unverified").details["lists"] == ["multi.surbl.org"]


async def test_a_parked_answer_does_not_hard_fail_the_sender_domain(dns: FakeDns) -> None:
    # A CRITICAL listing forces NO_GO, so it needs an answer in the listing range.
    _pass_domain_tests(dns)
    dns.set("example.com.dbl.nordspam.com", "A", "198.51.100.7")
    findings = await sender_dbl.run("example.com")
    assert score_findings(findings)["hard_gates_failed"] == []
    assert _one(findings, "sender_dbl.unverified").details["lists"] == ["dbl.nordspam.com"]


async def test_the_sender_scanned_row_counts_only_the_lists_that_answered(dns: FakeDns) -> None:
    # Nothing registered: no list passed its test, so no list checked the domain.
    scanned = _one(await sender_dbl.run("example.com"), "sender_dbl.scanned")
    assert "0 of 6" in scanned.message


# ── reverse DNS on the sending IP ──────────────────────────────────────────


async def test_a_sending_ip_with_matching_forward_and_reverse_dns_passes(
    dns: FakeDns,
) -> None:
    # A mail server should have a PTR record, and that name should resolve back to
    # the same address. Receivers treat a mismatch as a weak signal.
    dns.set("34.216.184.93.in-addr.arpa", "PTR", "mail.example.com")
    dns.set("mail.example.com", "A", "93.184.216.34")
    headers = {"received": ["from mail.example.com (mail.example.com [93.184.216.34]) by mx"]}
    assert not _failing(await sending_ip_dns.run(headers))


async def test_a_sending_ip_with_no_reverse_dns_is_reported(dns: FakeDns) -> None:
    headers = {"received": ["from mail.example.com (mail.example.com [93.184.216.34]) by mx"]}
    findings = await sending_ip_dns.run(headers)
    assert findings


async def test_no_received_chain_skips_the_reverse_lookup(dns: FakeDns) -> None:
    findings = await sending_ip_dns.run({})
    assert findings
    assert all(f.severity == "INFO" for f in findings), (
        "an unmeasurable signal must not carry a score penalty"
    )


# ── none of them raises ────────────────────────────────────────────────────


async def test_every_lookup_timing_out_does_not_raise(dns: FakeDns) -> None:
    # A blocklist refusing or rate-limiting a residential address is the normal
    # case for this tool's users, so a timeout must never fail the audit.
    headers = {"received": ["from mail.example.com (mail.example.com [93.184.216.34]) by mx"]}
    for host in ("zen.spamhaus.org", "bl.spamcop.net", "dbl.spamhaus.org"):
        dns.fail(f"34.216.184.93.{host}", "A", "timeout")
    assert await blacklist.run(headers)
    assert await sender_dbl.run("example.com")


# ── the docs state the list the code really queries ───────────────────


def test_each_doc_states_the_real_ip_blocklist_count() -> None:
    # CHECKS.md said 24 and the docstring said 9 while the code queried 31. A
    # number in a doc drifts unless something reads it. This reads the whole text,
    # because these docs wrap, and a count split over two lines must still match.
    stated = [
        (name, int(match.group(1)))
        for name in _DOCS_WITH_THE_COUNT
        for match in _IP_LIST_COUNT.finditer((ROOT / name).read_text())
    ]
    assert {name for name, _ in stated} == set(_DOCS_WITH_THE_COUNT), (
        f"the scan found no count in a doc, so it reads nothing there: {stated}"
    )
    wrong = [f"{name} says {count}" for name, count in stated if count != len(blacklist._RBLS)]
    assert not wrong, (
        f"_RBLS in engine/domain/dns/blacklist.py has {len(blacklist._RBLS)} entries, but "
        + ", ".join(wrong)
        + ". Change the doc to the real count."
    )


def test_each_doc_states_the_real_url_blocklist_count() -> None:
    # The IP count had this test and the URL count did not. Both drift the same way.
    stated = [
        (name, int(match.group(1)))
        for name in _DOCS_WITH_THE_COUNT
        for match in _URL_LIST_COUNT.finditer((ROOT / name).read_text())
    ]
    assert {name for name, _ in stated} == set(_DOCS_WITH_THE_COUNT), (
        f"the scan found no count in a doc, so it reads nothing there: {stated}"
    )
    wrong = [f"{name} says {count}" for name, count in stated if count != len(url_reputation._DBLS)]
    assert not wrong, (
        f"_DBLS in engine/domain/dns/url_reputation.py has {len(url_reputation._DBLS)} entries, "
        "but " + ", ".join(wrong) + ". Change the doc to the real count."
    )


def test_checks_md_lists_each_ip_blocklist_with_its_tier() -> None:
    rows = [
        _ROW.fullmatch(line) for line in (ROOT / "references/CHECKS.md").read_text().splitlines()
    ]
    listed = [row.groups() for row in rows if row]
    expected = [(label, host, sev.name) for label, host, sev, _ in blacklist._RBLS]
    assert listed == expected, (
        "the list table in references/CHECKS.md differs from _RBLS in "
        "engine/domain/dns/blacklist.py. Write one row for each entry, in the same order."
    )
