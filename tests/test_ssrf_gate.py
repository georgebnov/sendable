"""The unsubscribe probe must refuse to fetch anything but a public HTTP URL.

`unsubscribe_live` is the one check that makes an outbound request to a URL taken
from the email under audit. That URL is attacker-controlled: whoever wrote the
email chose it. Without a gate, an audit could be used to make the machine
running it fetch a cloud metadata endpoint or a service on the local network,
and report the response back. `_is_public_http_url` is that gate.
"""

from __future__ import annotations

import email.message
import urllib.error
import urllib.request

import pytest

from engine.domain.integrity.unsubscribe_live import (
    _build_opener,
    _is_public_http_url,
    _NoRedirect,
)


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata, link-local
        "http://127.0.0.1/",  # loopback
        "http://10.0.0.5/internal",  # private range
        "http://[::1]/",  # IPv6 loopback
        "ftp://example.com/",  # not HTTP
        "http://example.com:22/",  # port not allowed
        "not-a-url",
    ],
)
def test_blocks_unsafe_urls(url: str) -> None:
    assert _is_public_http_url(url) is False


@pytest.mark.parametrize("url", ["http://8.8.8.8/", "https://8.8.8.8/path"])
def test_allows_public_ip(url: str) -> None:
    # A numeric host resolves locally, so this needs no network.
    assert _is_public_http_url(url) is True


# ── the gate must survive a redirect ───────────────────────────────────────


def test_the_redirect_handler_refuses_instead_of_following() -> None:
    """A 30x must surface as an error, not be followed.

    `_probe_blocking` gates the URL it is handed and then opens it. urllib's
    default opener follows 301, 302, and 303 for up to ten hops, rewriting a POST
    into a body-less GET, and no hop target passes back through
    `_is_public_http_url`. A List-Unsubscribe URL on a public host answering
    `302 Location: http://169.254.169.254/...` therefore made the auditing
    machine fetch a cloud metadata endpoint, which is the exact request the gate
    exists to refuse. The URL is chosen by whoever wrote the email.
    """
    headers = email.message.Message()
    headers["Location"] = "http://169.254.169.254/latest/meta-data/"
    request = urllib.request.Request("https://example.com/u", method="POST")

    with pytest.raises(urllib.error.HTTPError) as caught:
        _NoRedirect().redirect_request(
            request,
            None,  # type: ignore[arg-type]
            302,
            "Found",
            headers,  # type: ignore[arg-type]
            "http://169.254.169.254/latest/meta-data/",
        )
    assert caught.value.code == 302, "the redirect must surface, not be followed"


def test_the_probe_uses_the_refusing_opener() -> None:
    # The handler only protects anything if the opener actually carries it.
    opener = _build_opener()
    assert any(isinstance(h, _NoRedirect) for h in opener.handlers), (  # type: ignore[attr-defined]
        "the opener must install the refusing redirect handler"
    )
