"""Outbound HTTP the audit is allowed to make.

Two checks fetch a URL derived from the email under audit: the unsubscribe probe
reads the List-Unsubscribe header, and the MTA-STS check reads a policy file at
`mta-sts.<sender domain>`. Both targets are chosen by whoever wrote the message.

That makes every such fetch a server-side request forgery risk. The guard has two
halves and both are needed:

  the address   a hostname resolving to a loopback, private, link-local, or
                otherwise internal address is refused. Cloud metadata lives at
                169.254.169.254, which is link-local.
  the redirect  urllib's default opener follows 301, 302, and 303 for up to ten
                hops and never re-checks where it lands, so a public host can
                redirect the fetch to an internal one. The opener here refuses,
                turning every redirect into an error the caller handles.

This module exists because the same defect was found twice in two different
checks. One guard, used by both, is harder to get wrong than two.
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit

# Ports a policy or unsubscribe endpoint may legitimately answer on. Anything
# else is a service that has no business receiving this request.
ALLOWED_PORTS = frozenset({80, 443})


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect, so a 30x surfaces as an error instead of a fetch.

    urllib's default handler follows a redirect without passing the new target
    back through any address check, which defeats the guard entirely.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


def build_opener(ssl_context: ssl.SSLContext | None = None) -> urllib.request.OpenerDirector:
    """An opener that will not follow a redirect of its own accord.

    `ssl_context` is passed through for an HTTPS fetch. It is stated explicitly
    rather than left to the default, so certificate verification is visible at
    the call site instead of being assumed.
    """
    handlers: list[urllib.request.BaseHandler] = [NoRedirect()]
    if ssl_context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=ssl_context))
    return urllib.request.build_opener(*handlers)


def is_public_address(host: str) -> bool:
    """True when every address this hostname resolves to is public.

    Every address, not the first: a hostname can publish one public address and
    one private one, and a resolver may hand back either.
    """
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    if not infos:
        return False
    for info in infos:
        raw = info[4][0]
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            return False
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_multicast
            or address.is_unspecified
        ):
            return False
    return True


def is_public_http_url(url: str, *, require_https: bool = False) -> bool:
    """True when `url` is an HTTP URL this audit may fetch.

    Checks the scheme, the port, and that the hostname resolves only to public
    addresses. It cannot close the window between this resolution and the one the
    connection makes, so a hostname whose answer changes between the two could
    still point somewhere internal. Refusing redirects keeps that window to a
    single lookup.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return False

    scheme = (parts.scheme or "").lower()
    if require_https:
        if scheme != "https":
            return False
    elif scheme not in ("http", "https"):
        return False

    try:
        port = parts.port
    except ValueError:
        return False
    if port is not None and port not in ALLOWED_PORTS:
        return False

    return is_public_address(parts.hostname or "")


__all__ = ["ALLOWED_PORTS", "NoRedirect", "build_opener", "is_public_address", "is_public_http_url"]
