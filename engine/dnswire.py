"""A small DNS client, built on the standard library.

The audit asks a resolver six kinds of question: TXT for SPF, DKIM and DMARC,
MX and A for where mail goes, NS for who runs the zone, PTR for whether a
sending address resolves back, and CNAME for a record that points elsewhere.
That is a narrow enough slice of DNS to write directly against the wire format
in RFC 1035, and writing it directly is what lets the skill run where nothing
can be installed.

This speaks UDP to the nameservers the machine already uses, and retries over
TCP when an answer arrives truncated, which TXT answers often do.
"""

from __future__ import annotations

import random
import socket
import struct

# The record types the audit asks for, and nothing else.
TYPE_CODES: dict[str, int] = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
}
_CODE_TYPES = {v: k for k, v in TYPE_CODES.items()}

_CLASS_IN = 1
_FLAG_RECURSION_DESIRED = 0x0100
_FLAG_TRUNCATED = 0x0200
_RCODE_MASK = 0x000F
_RCODE_NXDOMAIN = 3
_POINTER_MASK = 0xC0

# Used only when the machine lists no nameserver of its own, which happens in a
# container with no resolv.conf. Public resolvers, so a user is not stuck.
_FALLBACK_SERVERS = ("1.1.1.1", "8.8.8.8")


class DnsError(Exception):
    """A lookup that failed, carrying the category the caller reports."""

    def __init__(self, category: str) -> None:
        super().__init__(category)
        self.category = category


def nameservers() -> list[str]:
    """The resolvers this machine uses, falling back to public ones."""
    found: list[str] = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) > 1:
                        found.append(parts[1])
    except OSError:
        pass
    return found or list(_FALLBACK_SERVERS)


def reverse_name(ip: str) -> str:
    """The PTR name for an address, as `1.0.0.127.in-addr.arpa.`.

    Raises ValueError for anything that is not an address, which is what the
    caller already reports as a bad address.
    """
    import ipaddress

    address = ipaddress.ip_address(ip)
    if address.version == 4:
        return ".".join(reversed(address.exploded.split("."))) + ".in-addr.arpa."
    nibbles = address.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".ip6.arpa."


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        encoded = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode()
        if len(encoded) > 63:
            raise DnsError("error:LabelTooLong")
        out.append(len(encoded))
        out += encoded
    out.append(0)
    return bytes(out)


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Read a name, following compression pointers.

    A pointer can only ever point backwards, so following one that does not is
    how a malformed answer turns into an endless loop. Each hop is checked.
    """
    labels: list[str] = []
    seen: set[int] = set()
    cursor, after = offset, None
    while True:
        if cursor >= len(data):
            raise DnsError("error:TruncatedName")
        length = data[cursor]
        if length & _POINTER_MASK == _POINTER_MASK:
            pointer = struct.unpack_from("!H", data, cursor)[0] & 0x3FFF
            if pointer in seen or pointer >= cursor:
                raise DnsError("error:CompressionLoop")
            seen.add(pointer)
            if after is None:
                after = cursor + 2
            cursor = pointer
            continue
        cursor += 1
        if length == 0:
            break
        labels.append(data[cursor : cursor + length].decode("utf-8", errors="replace"))
        cursor += length
    return ".".join(labels), (after if after is not None else cursor)


def _decode_rdata(rdtype: str, data: bytes, offset: int, length: int) -> str:
    """One record, in the same text form dnspython produced."""
    if rdtype == "A":
        return socket.inet_ntop(socket.AF_INET, data[offset : offset + 4])
    if rdtype == "AAAA":
        return socket.inet_ntop(socket.AF_INET6, data[offset : offset + 16])
    if rdtype == "TXT":
        # A TXT record is a run of length-prefixed strings. A record longer
        # than 255 bytes arrives split, and the pieces join with nothing
        # between them, which is how a long DKIM key is published.
        parts, cursor, end = [], offset, offset + length
        while cursor < end:
            size = data[cursor]
            cursor += 1
            parts.append(data[cursor : cursor + size].decode("utf-8", errors="replace"))
            cursor += size
        return "".join(parts)
    if rdtype == "MX":
        preference = struct.unpack_from("!H", data, offset)[0]
        exchange, _ = _read_name(data, offset + 2)
        return f"{preference} {exchange.rstrip('.')}"
    if rdtype in ("NS", "PTR", "CNAME"):
        name, _ = _read_name(data, offset)
        return name.rstrip(".")
    return data[offset : offset + length].hex()


def _build_query(name: str, rdtype: str, query_id: int) -> bytes:
    header = struct.pack("!HHHHHH", query_id, _FLAG_RECURSION_DESIRED, 1, 0, 0, 0)
    question = _encode_name(name) + struct.pack("!HH", TYPE_CODES[rdtype], _CLASS_IN)
    return header + question


def _parse_answers(payload: bytes, rdtype: str, query_id: int) -> list[str]:
    if len(payload) < 12:
        raise DnsError("error:ShortAnswer")
    (
        answer_id,
        flags,
        question_count,
        answer_count,
        _authority_count,
        _additional_count,
    ) = struct.unpack_from("!HHHHHH", payload, 0)
    if answer_id != query_id:
        raise DnsError("error:AnswerIdMismatch")
    rcode = flags & _RCODE_MASK
    if rcode == _RCODE_NXDOMAIN:
        raise DnsError("nxdomain")
    if rcode != 0:
        raise DnsError(f"error:Rcode{rcode}")

    cursor = 12
    for _ in range(question_count):
        _, cursor = _read_name(payload, cursor)
        cursor += 4

    records: list[str] = []
    for _ in range(answer_count):
        _, cursor = _read_name(payload, cursor)
        type_code, _class_code, _ttl, length = struct.unpack_from("!HHIH", payload, cursor)
        cursor += 10
        # A name that answers with a CNAME when another type was asked for is
        # normal. Keep only the records that answer the question.
        if _CODE_TYPES.get(type_code) == rdtype:
            records.append(_decode_rdata(rdtype, payload, cursor, length))
        cursor += length

    if not records:
        raise DnsError("no_answer")
    return records


def _ask_udp(server: str, query: bytes, timeout: float) -> bytes:
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(query, (server, 53))
        return sock.recv(4096)


def _ask_tcp(server: str, query: bytes, timeout: float) -> bytes:
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((server, 53))
        sock.sendall(struct.pack("!H", len(query)) + query)
        header = _recv_exactly(sock, 2)
        return _recv_exactly(sock, struct.unpack("!H", header)[0])


def _recv_exactly(sock: socket.socket, count: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        chunk = sock.recv(count - len(chunks))
        if not chunk:
            raise DnsError("error:ConnectionClosed")
        chunks += chunk
    return bytes(chunks)


def resolve(name: str, rdtype: str, timeout: float = 3.0) -> list[str]:
    """Look a name up, or raise DnsError carrying the failure category."""
    rdtype = rdtype.upper()
    if rdtype not in TYPE_CODES:
        raise DnsError(f"error:UnsupportedType{rdtype}")

    query_id = random.SystemRandom().randrange(0, 0xFFFF)
    query = _build_query(name, rdtype, query_id)
    last = DnsError("no_nameservers")
    for server in nameservers():
        try:
            payload = _ask_udp(server, query, timeout)
            if len(payload) >= 4 and struct.unpack_from("!H", payload, 2)[0] & _FLAG_TRUNCATED:
                payload = _ask_tcp(server, query, timeout)
            return _parse_answers(payload, rdtype, query_id)
        except DnsError as exc:
            # A name that does not exist is the answer, not a reason to ask the
            # next resolver the same question.
            if exc.category in ("nxdomain", "no_answer"):
                raise
            last = exc
        except TimeoutError:
            last = DnsError("timeout")
        except OSError as exc:
            last = DnsError(f"error:{type(exc).__name__}")
    raise last


__all__ = ["DnsError", "nameservers", "resolve", "reverse_name"]
