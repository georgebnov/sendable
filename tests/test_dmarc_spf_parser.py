"""Reading a published SPF record into the shape the policy engine judges.

Two numbers out of this parser decide what a sender is told to do. The lookup
count is measured against the RFC 7208 cap of 10, and over that the record is a
PermError and SPF fails for every receiver. The `all` qualifier is how strict the
record is, and the advice chain uses it to decide whether tightening is the next
step. A miscount or a missed qualifier sends a sender to edit the wrong thing.
"""

from __future__ import annotations

import pytest

from engine.dmarc.spf_parser import parse


def test_no_records_means_no_spf() -> None:
    r = parse([])
    assert r.exists is False
    assert r.lookups == 0
    assert r.all_qualifier == ""


@pytest.mark.parametrize(
    ("record", "qualifier"),
    [
        ("v=spf1 -all", "-"),
        ("v=spf1 ~all", "~"),
        ("v=spf1 ?all", "?"),
        ("v=spf1 +all", "+"),
        # A bare `all` is `+all` by RFC 7208, which is allow-anyone. Reading it
        # as "no qualifier" would hide the most dangerous record a sender can
        # publish.
        ("v=spf1 all", "+"),
    ],
)
def test_every_all_qualifier_is_read(record: str, qualifier: str) -> None:
    assert parse([record]).all_qualifier == qualifier


def test_a_record_with_no_all_rule_reports_an_empty_qualifier() -> None:
    # Not "+". The record genuinely has no final rule, which is a different
    # finding from publishing +all on purpose.
    assert parse(["v=spf1 include:x.com"]).all_qualifier == ""


@pytest.mark.parametrize(
    ("record", "lookups"),
    [
        # The two records this tool meets most often, from a real audit.
        ("v=spf1 include:_spf.porkbun.com ~all", 1),
        ("v=spf1 include:spf.brevo.com mx ~all", 2),
        # Every mechanism that costs a lookup, counted once each.
        ("v=spf1 a mx ptr exists:x.com include:y.com redirect=z.com -all", 6),
        ("v=spf1 -all", 0),
    ],
)
def test_the_lookup_count_is_the_number_measured_against_the_cap(record: str, lookups: int) -> None:
    assert parse([record]).lookups == lookups


def test_ip4_and_ip6_cost_no_lookup() -> None:
    # They are answered from the record itself. Counting them would inflate the
    # number toward a cap it never approaches, and tell a sender to cut
    # mechanisms that are already free.
    assert parse(["v=spf1 ip4:1.2.3.4 ip6:::1 -all"]).lookups == 0


def test_redirect_counts_even_though_it_uses_an_equals_sign() -> None:
    # Every other lookup mechanism is `name:value`. `redirect=value` is the one
    # that is not, so a parser that only splits on ":" misses it and undercounts.
    assert parse(["v=spf1 redirect=_spf.example.com"]).lookups == 1


@pytest.mark.parametrize(
    "record",
    [
        "v=spf1 include:allmail.example.com -all",
        "v=spf1 exists:%{i}.all.example.com -all",
    ],
)
def test_the_letters_all_inside_a_hostname_are_not_the_all_rule(record: str) -> None:
    # The qualifier must come from the record's final rule, not from a domain
    # that happens to contain those three letters. Matching the hostname would
    # report a strict record as having no rule at all.
    assert parse([record]).all_qualifier == "-"


def test_more_than_one_record_is_counted_but_only_the_first_is_read() -> None:
    # Publishing two SPF records is a PermError, and `record_count` is how the
    # caller reports that. The parse still has to return something usable, and
    # it reads the first record rather than merging two that may disagree.
    r = parse(["v=spf1 a -all", "v=spf1 mx ~all"])
    assert r.record_count == 2
    assert r.lookups == 1
    assert r.all_qualifier == "-"


def test_a_record_split_across_quoted_strings_is_joined() -> None:
    # TXT records over 255 characters arrive as several strings. Whitespace is
    # normalised so a mechanism is not split in half by the join.
    r = parse(["v=spf1   include:a.example.com    mx    -all"])
    assert r.lookups == 2
    assert r.all_qualifier == "-"
    assert r.raw == "v=spf1   include:a.example.com    mx    -all"
