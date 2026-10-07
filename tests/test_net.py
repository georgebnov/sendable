"""The guard on every outbound request the audit makes.

Two checks fetch a URL derived from the email under audit: the unsubscribe probe
reads the List-Unsubscribe header, and the MTA-STS check reads a policy file at
`mta-sts.<sender domain>`. Both targets are chosen by whoever wrote the message,
which makes every such fetch a server-side request forgery risk.

This module exists because the same defect was found twice, in two different
checks, by two different review rounds. It is the one place that decides whether a
request is allowed, so it is the one place worth testing hard.
"""

from __future__ import annotations

import email.message
import urllib.error
import urllib.request
from collections.abc import Callable

import pytest

from engine.net import (
    ALLOWED_PORTS,
    NoRedirect,
    build_opener,
    is_public_address,
    is_public_http_url,
)


@pytest.fixture
def resolves(monkeypatch: pytest.MonkeyPatch) -> Callable[[dict[str, list[str]]], None]:
    """Pin what each hostname resolves to, so no test touches a real resolver."""

    def install(table: dict[str, list[str]]) -> None:
        import socket as socket_module

        def _fake(host: str, *args: object, **kwargs: object) -> list[tuple]:
            if host not in table:
                raise OSError(f"no answer for {host}")
            return [(2, 1, 6, "", (addr, 0)) for addr in table[host]]

        monkeypatch.setattr(socket_module, "getaddrinfo", _fake)

    return install


# ── addresses that must be refused ─────────────────────────────────────────


@pytest.mark.parametrize(
    ("label", "address"),
    [
        ("cloud metadata", "169.254.169.254"),
        ("link-local", "169.254.1.1"),
        ("loopback", "127.0.0.1"),
        ("private 10/8", "10.0.0.5"),
        ("private 172.16/12", "172.16.0.1"),
        ("private 192.168/16", "192.168.1.1"),
        ("unspecified", "0.0.0.0"),
        ("multicast", "224.0.0.1"),
        ("IPv6 loopback", "::1"),
        ("IPv6 link-local", "fe80::1"),
        ("IPv6 unique local", "fc00::1"),
    ],
)
def test_an_internal_address_is_refused(
    resolves: Callable[[dict[str, list[str]]], None], label: str, address: str
) -> None:
    resolves({"attacker.test": [address]})
    assert is_public_address("attacker.test") is False, f"{label} was allowed"


def test_a_public_address_is_allowed(
    resolves: Callable[[dict[str, list[str]]], None],
) -> None:
    resolves({"example.com": ["93.184.216.34"]})
    assert is_public_address("example.com") is True


def test_every_answer_must_be_public_not_just_the_first(
    resolves: Callable[[dict[str, list[str]]], None],
) -> None:
    # A hostname can publish one public address and one private one, and a
    # resolver may hand back either. Checking only the first leaves the attack
    # open half the time.
    resolves({"mixed.test": ["93.184.216.34", "127.0.0.1"]})
    assert is_public_address("mixed.test") is False


def test_a_hostname_that_does_not_resolve_is_refused(
    resolves: Callable[[dict[str, list[str]]], None],
) -> None:
    resolves({})
    assert is_public_address("nothing.test") is False


def test_an_empty_hostname_is_refused() -> None:
    assert is_public_address("") is False


# ── URLs ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/policy",
        "file:///etc/passwd",
        "gopher://example.com/",
        "not-a-url",
        "",
        "http://",
    ],
)
def test_a_non_http_url_is_refused(
    resolves: Callable[[dict[str, list[str]]], None], url: str
) -> None:
    resolves({"example.com": ["93.184.216.34"]})
    assert is_public_http_url(url) is False


@pytest.mark.parametrize("port", [22, 25, 3306, 5432, 6379, 8080, 11211])
def test_a_disallowed_port_is_refused(
    resolves: Callable[[dict[str, list[str]]], None], port: int
) -> None:
    # An unsubscribe endpoint answers on 80 or 443. Anything else is a service
    # that has no business receiving this request.
    resolves({"example.com": ["93.184.216.34"]})
    assert port not in ALLOWED_PORTS
    assert is_public_http_url(f"http://example.com:{port}/u") is False


@pytest.mark.parametrize("port", sorted(ALLOWED_PORTS))
def test_an_allowed_port_passes(
    resolves: Callable[[dict[str, list[str]]], None], port: int
) -> None:
    resolves({"example.com": ["93.184.216.34"]})
    assert is_public_http_url(f"http://example.com:{port}/u") is True


def test_a_plain_http_url_passes_by_default(
    resolves: Callable[[dict[str, list[str]]], None],
) -> None:
    resolves({"example.com": ["93.184.216.34"]})
    assert is_public_http_url("http://example.com/u") is True


def test_require_https_refuses_plain_http(
    resolves: Callable[[dict[str, list[str]]], None],
) -> None:
    # The MTA-STS policy file is defined as an HTTPS resource. Accepting http
    # there would let a redirect downgrade the fetch.
    resolves({"mta-sts.example.com": ["93.184.216.34"]})
    assert is_public_http_url("http://mta-sts.example.com/p", require_https=True) is False
    assert is_public_http_url("https://mta-sts.example.com/p", require_https=True) is True


def test_a_url_whose_host_is_internal_is_refused(
    resolves: Callable[[dict[str, list[str]]], None],
) -> None:
    resolves({"internal.test": ["10.0.0.5"]})
    assert is_public_http_url("https://internal.test/policy") is False


def test_a_malformed_port_is_refused(
    resolves: Callable[[dict[str, list[str]]], None],
) -> None:
    resolves({"example.com": ["93.184.216.34"]})
    assert is_public_http_url("http://example.com:notaport/u") is False


# ── redirects ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_every_redirect_is_refused(code: int) -> None:
    # urllib's default handler follows 301, 302, and 303 for up to ten hops and
    # never re-checks the target, which defeats the address guard entirely.
    headers = email.message.Message()
    headers["Location"] = "http://169.254.169.254/latest/meta-data/"
    request = urllib.request.Request("https://example.com/u", method="POST")

    with pytest.raises(urllib.error.HTTPError) as caught:
        NoRedirect().redirect_request(
            request,
            None,  # type: ignore[arg-type]
            code,
            "Redirect",
            headers,  # type: ignore[arg-type]
            "http://169.254.169.254/latest/meta-data/",
        )
    assert caught.value.code == code


def test_the_opener_installs_the_refusing_handler() -> None:
    opener = build_opener()
    assert any(isinstance(h, NoRedirect) for h in opener.handlers)  # type: ignore[attr-defined]


def test_the_opener_carries_a_supplied_ssl_context() -> None:
    # Certificate verification is stated at the call site rather than assumed
    # from a default that a later change could alter.
    import ssl

    context = ssl.create_default_context()
    opener = build_opener(ssl_context=context)
    https = [
        h
        for h in opener.handlers  # type: ignore[attr-defined]
        if isinstance(h, urllib.request.HTTPSHandler)
    ]
    assert https, "an https handler must be installed when a context is given"
