"""The sender's own mail server, as a receiver would find it.

An audit of a sending domain checks the MX records point somewhere real, that the
host is not a bare IP or a CNAME (both of which RFC 1035 and 5321 forbid for an MX
target), and that the server is not an open relay.

This is the one check that opens a TCP connection, so it is also the one that must
refuse to connect when there is nothing legitimate to connect to.
"""

from __future__ import annotations

import asyncio

import pytest

from engine.domain import dns_client
from engine.domain.dns import smtp_probe
from engine.report import Finding


@pytest.fixture
def no_smtp(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record every host the probe tries to connect to, and connect to none.

    Every hostname resolves to a public address by default, because the probe now
    refuses a host that resolves internally and would otherwise never attempt a
    connection at all. A test about that guard overrides the resolver itself.
    """
    attempted: list[str] = []

    import socket as socket_module

    monkeypatch.setattr(
        socket_module, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))]
    )

    class _Refused:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            attempted.append(host)
            raise OSError("connection refused in tests")

        def __enter__(self):  # pragma: no cover - never reached
            return self

        def __exit__(self, *exc: object) -> None:  # pragma: no cover
            return None

    import smtplib

    monkeypatch.setattr(smtplib, "SMTP", _Refused)
    return attempted


def _run(records: dict[tuple[str, str], tuple[str, ...]]) -> list[Finding]:
    """Run the probe against a fixed set of DNS answers."""

    def _fake(name: str, rdtype: str) -> dns_client.DnsAnswer:
        key = (rdtype.upper(), name.lower().rstrip("."))
        if key in records:
            return dns_client.DnsAnswer(
                rdtype=key[0], name=name, records=records[key], error=None, elapsed_ms=1
            )
        return dns_client.DnsAnswer(
            rdtype=key[0], name=name, records=(), error="nxdomain", elapsed_ms=1
        )

    dns_client._cache.clear()
    original = dns_client._query_sync
    dns_client._query_sync = _fake  # type: ignore[assignment]
    try:
        return asyncio.run(smtp_probe.run("example.com"))
    finally:
        dns_client._query_sync = original  # type: ignore[assignment]


def _by(findings: list[Finding], check: str) -> Finding | None:
    return next((f for f in findings if f.check == check), None)


# ── a null MX means the domain accepts no mail ─────────────────────────────


def test_a_null_mx_is_recognised(no_smtp: list[str]) -> None:
    """RFC 7505: a single MX of preference 0 pointing at "." means this domain
    accepts no mail at all, which is a deliberate and correct configuration.

    `dns_client` formats an MX as "<preference> <exchange>" and strips the
    trailing dot, so a null MX arrives as "0 " with an empty exchange. The check
    looked for a literal " ." and therefore never fired.
    """
    findings = _run({("MX", "example.com"): ("0 ",)})
    null_mx = _by(findings, "smtp.null_mx")
    assert null_mx is not None, "a null MX was not recognised"
    assert null_mx.passed is True


def test_a_null_mx_domain_is_never_connected_to(no_smtp: list[str]) -> None:
    # The domain has said it accepts no mail. Opening a connection to the empty
    # hostname that is left behind is both pointless and wrong.
    _run({("MX", "example.com"): ("0 ",)})
    assert no_smtp == [], f"connected to {no_smtp} for a domain that accepts no mail"


def test_a_null_mx_does_not_produce_findings_about_an_empty_host(
    no_smtp: list[str],
) -> None:
    # Before the fix these read ": not a bare IP literal." with nothing before the
    # colon, because the hostname was the empty string.
    findings = _run({("MX", "example.com"): ("0 ",)})
    for finding in findings:
        assert not finding.message.startswith(":"), finding.message


# ── no MX at all ───────────────────────────────────────────────────────────


def test_a_domain_with_no_mx_is_reported(no_smtp: list[str]) -> None:
    resolution = _by(_run({}), "smtp.dns_resolution")
    assert resolution is not None
    assert resolution.passed is False


def test_a_domain_with_no_mx_is_never_connected_to(no_smtp: list[str]) -> None:
    _run({})
    assert no_smtp == []


# ── MX targets that break the rules ────────────────────────────────────────


def test_a_bare_ip_as_an_mx_target_is_reported(no_smtp: list[str]) -> None:
    # RFC 1035 and 5321 require an MX target to be a hostname. Several receivers
    # refuse mail from a domain whose MX is an address literal.
    findings = _run({("MX", "example.com"): ("10 93.184.216.34",)})
    bare = _by(findings, "smtp.mx_bare_ip")
    assert bare is not None
    assert bare.passed is False


def test_an_mx_target_that_is_a_cname_is_reported(no_smtp: list[str]) -> None:
    # RFC 2181 forbids this. A receiver that follows the rule strictly will fail
    # to deliver at all.
    findings = _run(
        {
            ("MX", "example.com"): ("10 mail.example.com",),
            ("CNAME", "mail.example.com"): ("real.example.net",),
        }
    )
    cname = _by(findings, "smtp.mx_cname_violation")
    assert cname is not None
    assert cname.passed is False


def test_a_well_formed_mx_passes_both_rules(no_smtp: list[str]) -> None:
    findings = _run({("MX", "example.com"): ("10 mail.example.com",)})
    for check in ("smtp.mx_bare_ip", "smtp.mx_cname_violation"):
        finding = _by(findings, check)
        assert finding is not None
        assert finding.passed is True


def test_every_mx_target_is_audited_in_preference_order(no_smtp: list[str]) -> None:
    # Each MX is a delivery path a sender may actually be routed through, so each
    # is checked. Lower preference first, which is the order mail takes.
    _run({("MX", "example.com"): ("50 backup.example.com", "10 primary.example.com")})
    assert no_smtp == ["primary.example.com", "backup.example.com"]


# ── the open-relay probe ───────────────────────────────────────────────────


def test_a_refused_connection_is_reported_as_inconclusive(no_smtp: list[str]) -> None:
    # A probe that cannot connect has not proved the server is safe. Reporting a
    # pass would tell the user something the audit did not establish.
    findings = _run({("MX", "example.com"): ("10 mail.example.com",)})
    relay = _by(findings, "smtp.open_relay")
    assert relay is not None
    assert "inconclusive" in relay.message.lower()


def test_a_dns_failure_does_not_raise(no_smtp: list[str]) -> None:
    def _fail(name: str, rdtype: str) -> dns_client.DnsAnswer:
        return dns_client.DnsAnswer(
            rdtype=rdtype.upper(), name=name, records=(), error="timeout", elapsed_ms=1
        )

    dns_client._cache.clear()
    original = dns_client._query_sync
    dns_client._query_sync = _fail  # type: ignore[assignment]
    try:
        assert asyncio.run(smtp_probe.run("example.com"))
    finally:
        dns_client._query_sync = original  # type: ignore[assignment]


# ── the probe must not connect to an internal address ──────────────────────


@pytest.mark.parametrize(
    "mx_target",
    ["169.254.169.254", "127.0.0.1", "10.0.0.5", "192.168.1.1", "internal.test"],
)
def test_an_mx_pointing_somewhere_internal_is_not_connected_to(
    no_smtp: list[str], monkeypatch: pytest.MonkeyPatch, mx_target: str
) -> None:
    """The MX host is chosen by whoever controls the audited domain.

    An audit resolves the sender domain's MX and opens a TCP connection to it on
    port 25. Publishing an MX of 169.254.169.254 therefore made the auditing
    machine connect to the cloud metadata address. This is the same class as the
    unsubscribe probe and the MTA-STS fetch, and the third place it appeared.
    """
    import socket as socket_module

    monkeypatch.setattr(
        socket_module,
        "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("169.254.169.254", 0))],
    )
    _run({("MX", "example.com"): (f"10 {mx_target}",)})
    assert no_smtp == [], f"connected to {no_smtp}, which resolves internally"


def test_a_public_mx_is_still_probed(no_smtp: list[str], monkeypatch: pytest.MonkeyPatch) -> None:
    import socket as socket_module

    monkeypatch.setattr(
        socket_module, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))]
    )
    _run({("MX", "example.com"): ("10 mail.example.com",)})
    assert no_smtp == ["mail.example.com"]
