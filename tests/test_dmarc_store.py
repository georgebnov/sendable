"""The local store for DMARC aggregate reports.

The one behaviour that matters most here is deduplication. A mailbox gets re-read,
and a provider sometimes re-sends. Storing the same report twice would double every
message count in the window, making a sender look twice as busy as it is and
corrupting the clean-streak judgement that gates policy advancement.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from engine.dmarc.parser import parse
from store.dmarc import SCHEMA_VERSION, DmarcStore


def _xml(
    *,
    org: str = "google.com",
    report_id: str | None = "g-0001",
    day: int = 1,
    domain: str = "example.com",
    ip: str = "209.85.220.41",
    count: int = 100,
) -> bytes:
    rid = f"<report_id>{report_id}</report_id>" if report_id is not None else ""
    begin = 1759000000 + day * 86400
    return f"""<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>{org}</org_name>
    <email>dmarc@{org}</email>
    {rid}
    <date_range><begin>{begin}</begin><end>{begin + 86399}</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>{domain}</domain><adkim>r</adkim><aspf>r</aspf><p>none</p><pct>100</pct>
  </policy_published>
  <record>
    <row><source_ip>{ip}</source_ip><count>{count}</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>{domain}</header_from></identifiers>
    <auth_results>
      <dkim><domain>{domain}</domain><selector>s1</selector><result>pass</result></dkim>
      <spf><domain>{domain}</domain><result>pass</result></spf>
    </auth_results>
  </record>
</feedback>
""".encode()


@pytest.fixture
def store(tmp_path: Path) -> DmarcStore:
    return DmarcStore(tmp_path / ".sendable")


# ── the compressed formats providers actually send ─────────────────────────


def test_plain_xml_parses() -> None:
    assert parse(_xml()).org_name == "google.com"


def test_gzipped_xml_parses() -> None:
    # Google sends .xml.gz.
    assert parse(gzip.compress(_xml())).org_name == "google.com"


def test_a_malformed_feed_raises_a_clear_error() -> None:
    with pytest.raises(ValueError):
        parse(b"<html>this is not a dmarc report</html>")


# ── writing ────────────────────────────────────────────────────────────────


def test_save_writes_one_file_under_the_domain(store: DmarcStore) -> None:
    path, is_new = store.save(parse(_xml()))
    assert is_new is True
    assert path.is_file()
    assert path.parent.name == "example.com"
    record = json.loads(path.read_text())
    assert record["schema"] == SCHEMA_VERSION
    assert record["report"]["org_name"] == "google.com"


def test_the_file_name_leads_with_the_period_and_names_the_reporter(
    store: DmarcStore,
) -> None:
    path, _ = store.save(parse(_xml(org="microsoft.com", day=5)))
    assert path.name.startswith("2025")
    assert "microsoft.com" in path.name


def test_the_same_report_ingested_twice_is_stored_once(store: DmarcStore) -> None:
    # The whole reason identity comes from the provider's report id. A duplicate
    # would double every message count in the window.
    first, new_first = store.save(parse(_xml()))
    second, new_second = store.save(parse(_xml()))
    assert new_first is True
    assert new_second is False
    assert first == second
    assert len(list(first.parent.glob("*.json"))) == 1


def test_the_same_report_gzipped_and_plain_is_stored_once(store: DmarcStore) -> None:
    # The transport does not change the report, so neither may the identity.
    store.save(parse(_xml()))
    _, is_new = store.save(parse(gzip.compress(_xml())))
    assert is_new is False


def test_two_reporters_on_the_same_day_are_both_kept(store: DmarcStore) -> None:
    # Microsoft and Google reporting the same day is independent evidence, and the
    # question "did the other one see this too" needs both.
    store.save(parse(_xml(org="google.com", report_id="g-1")))
    store.save(parse(_xml(org="microsoft.com", report_id="m-1")))
    assert len(store.reports_for("example.com", days=10_000)) == 2


def test_a_report_with_no_report_id_still_deduplicates(store: DmarcStore) -> None:
    # Some reporters omit the id. Identity then comes from the period and the
    # record set, which is stable for the same attachment.
    store.save(parse(_xml(report_id=None)))
    _, is_new = store.save(parse(_xml(report_id=None)))
    assert is_new is False


def test_two_reports_with_no_id_but_different_records_are_both_kept(
    store: DmarcStore,
) -> None:
    store.save(parse(_xml(report_id=None, ip="1.1.1.1")))
    _, is_new = store.save(parse(_xml(report_id=None, ip="2.2.2.2")))
    assert is_new is True


def test_reports_for_different_domains_are_kept_apart(store: DmarcStore) -> None:
    store.save(parse(_xml(domain="example.com", report_id="a")))
    store.save(parse(_xml(domain="other.test", report_id="b")))
    assert len(store.reports_for("example.com", days=10_000)) == 1
    assert len(store.reports_for("other.test", days=10_000)) == 1
    assert store.domains() == ["example.com", "other.test"]


# ── reading ────────────────────────────────────────────────────────────────


def test_no_reports_for_an_unknown_domain(store: DmarcStore) -> None:
    assert store.reports_for("never-seen.example") == []
    assert store.known_providers("never-seen.example") == set()
    assert store.domains() == []


def test_a_report_outside_the_window_is_not_returned(store: DmarcStore) -> None:
    # The window means "recent evidence". A year-old report says nothing about
    # whether it is safe to tighten the policy today.
    store.save(parse(_xml(day=1)))
    assert store.reports_for("example.com", days=1) == []
    assert len(store.reports_for("example.com", days=10_000)) == 1


def test_a_corrupt_file_is_skipped_not_fatal(store: DmarcStore) -> None:
    store.save(parse(_xml()))
    (store.domain_dir("example.com") / "20260101-bad-000000000000.json").write_text("{not json")
    assert len(store.reports_for("example.com", days=10_000)) == 1


def test_a_file_that_is_json_but_not_a_report_is_skipped(store: DmarcStore) -> None:
    store.save(parse(_xml()))
    (store.domain_dir("example.com") / "20260101-bad-111111111111.json").write_text(
        json.dumps({"schema": 1, "report": {"records": "not a list"}})
    )
    assert len(store.reports_for("example.com", days=10_000)) == 1


def test_known_providers_accumulates_across_reports(store: DmarcStore) -> None:
    # The classifier uses this to tell a new source from one that has sent before,
    # which is the difference between a spoof starting and a provider adding an IP.
    store.save(parse(_xml(ip="209.85.220.41", report_id="a")))
    store.save(parse(_xml(ip="198.51.100.9", report_id="b")))
    assert len(store.known_providers("example.com")) == 2


def test_known_providers_is_not_limited_to_the_window(store: DmarcStore) -> None:
    # A provider that sent last month is still one you know. Forgetting it would
    # raise a false new-sender alarm the next time it sends.
    store.save(parse(_xml(day=1)))
    assert store.reports_for("example.com", days=1) == []
    assert store.known_providers("example.com") != set()
