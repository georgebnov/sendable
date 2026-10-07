"""BIMI check — record offered only when DMARC is enforced.

BIMI is ignored by receivers below quarantine/reject, so we must not hand
out a logo record that can't work yet; and when eligible, we must give a
copy-paste TXT record.
"""

from __future__ import annotations

from engine.domain.dns import modern_records


class _Ans:
    def __init__(self, ok, records=(), error=None):
        self.ok = ok
        self.records = list(records)
        self.error = error


def _fake_query(dmarc_records):
    async def q(name, rtype):
        if name.startswith("_dmarc."):
            return _Ans(True, dmarc_records)
        return _Ans(True, [])  # no BIMI record published

    return q


async def test_offers_record_when_reject(monkeypatch):
    monkeypatch.setattr(modern_records, "query", _fake_query(["v=DMARC1; p=reject"]))
    f = (await modern_records._run_bimi("avateq.com"))[0]
    assert f.details["eligible"] is True
    assert f.details["dmarc_policy"] == "reject"
    assert f.details["suggested_record"] == "v=BIMI1; l=https://avateq.com/bimi/logo.svg;"
    assert f.details["record_host"] == "default._bimi.avateq.com"


async def test_no_record_when_policy_none(monkeypatch):
    monkeypatch.setattr(modern_records, "query", _fake_query(["v=DMARC1; p=none"]))
    f = (await modern_records._run_bimi("avateq.com"))[0]
    assert f.details["eligible"] is False
    assert "suggested_record" not in f.details
    assert "quarantine or reject" in f.message


async def test_no_record_when_no_dmarc(monkeypatch):
    monkeypatch.setattr(modern_records, "query", _fake_query([]))
    f = (await modern_records._run_bimi("avateq.com"))[0]
    assert f.details["eligible"] is False
    assert f.details["dmarc_policy"] is None
