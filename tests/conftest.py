"""Shared fixtures.

Every test here runs with no network and no model call. The audit is called with
`domain_health=False`, which skips the DNS, blocklist, and SMTP checks, and the
`no_llm` fixture clears OPENAI_API_KEY so the model-backed checks take their
documented skip path and report INFO.

That combination makes the suite deterministic. A test that depends on a DNS
answer or on what a model said this time is a test that fails for reasons the
code did not cause.
"""

from __future__ import annotations

import pathlib

import pytest

from engine.domain.dns_client import DnsAnswer

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def no_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove the API key so no test can reach a model.

    Autouse on purpose. A single test that forgets this would make a paid call
    and return a different answer on the next run.
    """
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)


def load(name: str) -> bytes:
    """Read a .eml fixture by file name."""
    path = FIXTURES / name
    if not path.is_file():
        raise FileNotFoundError(f"no fixture named {name} in {FIXTURES}")
    return path.read_bytes()


class FakeDns:
    """A DNS zone held in a dict, so a check can be tested without a network.

    Every lookup in the engine funnels through `dns_client._query_sync`, so
    replacing that one function controls SPF, DKIM, DMARC, MX, the blocklist
    fan-out, and reverse lookups at once.

    Register answers with `set`, and anything not registered answers NXDOMAIN,
    which is what a real resolver returns for a name that does not exist. A test
    therefore states only the records it cares about.
    """

    def __init__(self) -> None:
        self._zone: dict[tuple[str, str], tuple[str, ...]] = {}
        self._errors: dict[tuple[str, str], str] = {}
        self.asked: list[tuple[str, str]] = []

    @staticmethod
    def _key(name: str, rdtype: str) -> tuple[str, str]:
        return (rdtype.upper(), name.lower().rstrip("."))

    def set(self, name: str, rdtype: str, *records: str) -> FakeDns:
        self._zone[self._key(name, rdtype)] = records
        return self

    def fail(self, name: str, rdtype: str, error: str = "timeout") -> FakeDns:
        """Make one lookup report a failure, to test the degraded path."""
        self._errors[self._key(name, rdtype)] = error
        return self

    def answer(self, name: str, rdtype: str) -> DnsAnswer:
        key = self._key(name, rdtype)
        self.asked.append(key)
        if key in self._errors:
            return DnsAnswer(
                rdtype=key[0], name=name, records=(), error=self._errors[key], elapsed_ms=1
            )
        records = self._zone.get(key)
        if records is None:
            return DnsAnswer(rdtype=key[0], name=name, records=(), error="nxdomain", elapsed_ms=1)
        return DnsAnswer(rdtype=key[0], name=name, records=records, error=None, elapsed_ms=1)


@pytest.fixture
def dns(monkeypatch: pytest.MonkeyPatch) -> FakeDns:
    """A FakeDns wired into the engine, with the process cache cleared.

    The cache matters: dns_client keeps answers for an hour in a module-level
    dict, so without clearing it one test would see another test's zone.
    """
    from engine.domain import dns_client

    dns_client._cache.clear()
    fake = FakeDns()
    monkeypatch.setattr(dns_client, "_query_sync", fake.answer)
    return fake
