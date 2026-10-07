"""The unsubscribe probe must refuse to fetch anything but a public HTTP URL.

`unsubscribe_live` is the one check that makes an outbound request to a URL taken
from the email under audit. That URL is attacker-controlled: whoever wrote the
email chose it. Without a gate, an audit could be used to make the machine
running it fetch a cloud metadata endpoint or a service on the local network,
and report the response back. `_is_public_http_url` is that gate.
"""

from __future__ import annotations

import pytest

from engine.domain.integrity.unsubscribe_live import _is_public_http_url


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
