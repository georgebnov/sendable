"""How to read an answer from a DNS blocklist.

Every list keeps a test name that must always read as listed. RFC 5782 fixes it
as `2.0.0.127.<list>` for an IP list and `test.<list>` for a domain list.

An NXDOMAIN answer about a sender means "not listed" only when the list passed
its test in the same audit. Spamhaus answers NXDOMAIN for its own test address
through some public resolvers, and a network filter can remove every 127.x
answer. Without the test, both read as clean, and a listed sender gets a clean
report. There is no state between runs, so each audit tests each list again.

A passed test does not prove every lookup after it. The resolver can hold the
test answer in its cache and still get a refusal for a new name.
"""

from __future__ import annotations

from enum import Enum
from ipaddress import IPv4Address, IPv4Network

from ...report import Finding
from ...severity import Severity
from ..dns_client import DnsAnswer

# RFC 5782: a listing is an address in 127.0.0.0/8. Anything else came from a
# parked domain or a resolver that rewrites NXDOMAIN.
_LISTING_RANGE = IPv4Network("127.0.0.0/8")
# The operators use this range to refuse a query: .252 is a wrong zone, .254 is a
# public resolver, .255 is a rate limit.
_REFUSAL_RANGE = IPv4Network("127.255.255.0/24")
# The "query refused" answer of URIBL and SURBL.
_REFUSAL = IPv4Address("127.0.0.1")
# A list here answers about senders it does not list. Only these codes mean listed.
# Every other code in the listing range is a usable "not listed", 127.0.0.1 too.
# Hostkarma, http://wiki.junkemailfilter.com/index.php/Spam_DNS_Lists: 127.0.0.1
# white, .2 black, .3 yellow, .4 brown ("not yet enough to blacklist"), .5 NOBL,
# 127.0.1.x the use of QUIT, and 127.0.2.x the age of the sender.
_LISTING_CODES = {"hostkarma.junkemailfilter.com": frozenset({"127.0.0.2"})}


class Reading(Enum):
    """What one answer says about one name on one list."""

    LISTED = "listed"
    CLEAN = "clean"
    UNKNOWN = "unknown"


def _in_listing_range(record: str) -> bool:
    try:
        address = IPv4Address(record)
    except ValueError:
        return False
    return address in _LISTING_RANGE and address not in _REFUSAL_RANGE


def _is_listing_code(record: str, host: str) -> bool:
    if host in _LISTING_CODES:
        return record in _LISTING_CODES[host]
    return _in_listing_range(record) and IPv4Address(record) != _REFUSAL


def has_listing_code(answer: DnsAnswer, host: str) -> bool:
    return any(_is_listing_code(record, host) for record in answer.records)


def _says_not_listed(answer: DnsAnswer, host: str) -> bool:
    if answer.error == "nxdomain":
        return True
    return (
        host in _LISTING_CODES
        and bool(answer.records)
        and all(map(_in_listing_range, answer.records))
    )


def read_answer(answer: DnsAnswer, host: str, *, test_passed: bool) -> Reading:
    """Read 1 answer from 1 list. A listing stands without a passed test, because some
    lists skip the test name and a listed answer is evidence on its own. Clean does not."""
    if has_listing_code(answer, host):
        return Reading.LISTED
    if test_passed and _says_not_listed(answer, host):
        return Reading.CLEAN
    return Reading.UNKNOWN


def not_checked(host: str, name: str, answer: DnsAnswer) -> dict[str, str]:
    """1 row of `details.unchecked`: the list, the name asked about, and the answer."""
    return {"list": host, "name": name, "answer": answer.error or ", ".join(answer.records)}


def unverified_finding(
    check: str,
    unchecked: list[dict[str, str]],
    total: int,
    subject: str,
    source: str = "user_content",
) -> Finding:
    """The 1 finding for every list that gave no usable answer. INFO has no penalty,
    so a list that was not checked neither lifts nor cuts the score."""
    hosts = list(dict.fromkeys(row["list"] for row in unchecked))
    return Finding(
        check=check,
        severity=Severity.INFO,
        passed=False,
        message=(
            f"Sendable could not check {subject} against {len(hosts)} of {total} blocklists "
            f"from this network: {', '.join(hosts)}. These count as not checked, not as "
            "clean. Run the audit again from another network, for example a cloud server. "
            "If a list stays here from several networks, it may no longer offer a working "
            "public check."
        ),
        details={"lists": hosts, "unchecked": unchecked},
        source=source,
    )
