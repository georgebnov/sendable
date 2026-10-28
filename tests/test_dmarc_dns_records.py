"""Reading the live SPF and DMARC records off a domain.

This is what makes the DMARC advice current. An aggregate report describes mail
sent days ago, so a record the sender fixed today is invisible in it, and the
advice chain reads DNS to see the fix. Every number it reads here feeds a
recommendation, so a default applied wrongly tells a sender to change a record
that was already correct.

The module calls `dns.resolver.resolve` directly rather than going through
`engine/domain/dns_client.py`, so the `dns` fixture cannot reach it. These tests
stub its single lookup function instead, which keeps the suite off the network
and isolates the parsing, which is where the judgement lives.
"""

from __future__ import annotations

import pytest

from engine.dmarc import dns_records
from engine.dmarc.dns_records import _parse_dmarc_txt, _strip_txt, read_dmarc, read_spf


@pytest.fixture(autouse=True)
def _clear_caches() -> None:
    # Both caches are module-level dicts that live for the process. Without this
    # one test's domain answers another test's lookup.
    dns_records._spf_cache.clear()
    dns_records._dmarc_cache.clear()


@pytest.fixture
def txt(monkeypatch: pytest.MonkeyPatch):
    """Answer one TXT lookup per name, and count the lookups made."""
    calls: list[str] = []

    def install(zone: dict[str, list[str]]) -> list[str]:
        def fake(name: str) -> list[str]:
            calls.append(name)
            return zone.get(name, [])

        monkeypatch.setattr(dns_records, "_query_txt", fake)
        return calls

    return install


# ── the DMARC record ──────────────────────────────────────────────────


def test_a_real_published_record_is_read() -> None:
    # mykava.app, as published. The defaults matter as much as the stated tags:
    # a record with no pct is 100%, and alignment is relaxed unless it says
    # otherwise, so reading either as absent would misreport the policy.
    r = _parse_dmarc_txt("v=DMARC1; p=quarantine; rua=mailto:info@mykava.app")
    assert (r.exists, r.p, r.pct, r.adkim, r.aspf) == (True, "quarantine", 100, "r", "r")
    assert r.sp is None


def test_strict_alignment_is_read() -> None:
    r = _parse_dmarc_txt("v=DMARC1; p=reject; adkim=s; aspf=s")
    assert (r.adkim, r.aspf) == ("s", "s")


def test_a_subdomain_policy_is_read_separately_from_the_domain_policy() -> None:
    # `sp` governs subdomains. Collapsing it into `p` would report a domain as
    # protected when only its apex is.
    r = _parse_dmarc_txt("v=DMARC1; p=reject; sp=none")
    assert (r.p, r.sp) == ("reject", "none")


def test_pct_zero_is_kept_and_not_defaulted() -> None:
    # `p=reject; pct=0` enforces on no mail at all, which is monitoring wearing
    # a reject label. Defaulting it to 100 would report the domain as enforcing.
    assert _parse_dmarc_txt("v=DMARC1; p=reject; pct=0").pct == 0


def test_an_unparseable_pct_falls_back_to_100_rather_than_raising() -> None:
    # A typo in one tag must not take down the whole read, and 100 is what the
    # RFC says an absent pct means, so it is the safe reading.
    assert _parse_dmarc_txt("v=DMARC1; p=reject; pct=abc").pct == 100


def test_tag_names_and_values_are_case_insensitive() -> None:
    r = _parse_dmarc_txt("v=DMARC1; P=REJECT; ADKIM=S")
    assert (r.p, r.adkim) == ("reject", "s")


def test_a_record_with_no_policy_tag_reports_an_empty_policy() -> None:
    # Not "none". The tag is absent, which is a malformed record, and that is a
    # different finding from a sender choosing p=none deliberately.
    assert _parse_dmarc_txt("v=DMARC1; rua=mailto:x@example.com").p == ""


def test_a_stray_tag_without_an_equals_sign_is_skipped() -> None:
    r = _parse_dmarc_txt("v=DMARC1; p=reject; garbage; adkim=s")
    assert (r.p, r.adkim) == ("reject", "s")


# ── the lookups, and what gets filtered ───────────────────────────────


def test_a_domain_with_no_dmarc_record_reports_absent(txt) -> None:
    txt({})
    assert read_dmarc("example.com").exists is False


def test_dmarc_is_read_from_the_dmarc_subdomain(txt) -> None:
    calls = txt({"_dmarc.example.com": ["v=DMARC1; p=reject"]})
    assert read_dmarc("example.com").p == "reject"
    assert calls == ["_dmarc.example.com"]


def test_only_a_v_spf1_record_is_treated_as_spf(txt) -> None:
    # A domain's TXT records carry site verification, Postmaster Tools tokens and
    # anything else. Reading one of those as an SPF record would parse nonsense
    # and report a lookup count for it.
    txt(
        {
            "example.com": [
                "google-site-verification=abc123",
                "v=spf1 include:_spf.google.com ~all",
                "some-other-token",
            ]
        }
    )
    r = read_spf("example.com")
    assert r.exists is True
    assert r.record_count == 1
    assert (r.lookups, r.all_qualifier) == (1, "~")


def test_a_domain_with_no_spf_record_reports_absent(txt) -> None:
    txt({"example.com": ["google-site-verification=abc123"]})
    assert read_spf("example.com").exists is False


# ── the cache ─────────────────────────────────────────────────────────


def test_a_second_read_of_the_same_domain_does_not_query_again(txt) -> None:
    # One run of the DMARC advice reads the same domain several times. Without
    # the cache that is several identical lookups per run.
    calls = txt({"example.com": ["v=spf1 -all"], "_dmarc.example.com": ["v=DMARC1; p=none"]})
    read_spf("example.com")
    read_spf("example.com")
    read_dmarc("example.com")
    read_dmarc("example.com")
    assert calls == ["example.com", "_dmarc.example.com"]


def test_two_domains_do_not_share_a_cache_entry(txt) -> None:
    txt({"a.test": ["v=spf1 -all"], "b.test": ["v=spf1 include:x.com mx ~all"]})
    assert read_spf("a.test").lookups == 0
    assert read_spf("b.test").lookups == 2


# ── the TXT unwrapping ────────────────────────────────────────────────


def test_a_txt_value_split_across_quoted_strings_is_joined() -> None:
    # A TXT record over 255 characters arrives as several quoted strings, and
    # dnspython hands them back with the quotes. Joining without stripping them
    # leaves quote marks inside a mechanism.
    assert _strip_txt('"v=spf1 include:a.example.com " "include:b.example.com -all"') == (
        "v=spf1 include:a.example.com include:b.example.com -all"
    )


def test_an_unquoted_txt_value_is_passed_through() -> None:
    assert _strip_txt("  v=spf1 -all  ") == "v=spf1 -all"
