"""The DNS client, tested on bytes rather than on the network.

Rule 4: the suite reaches nothing. A resolver is the one piece where that is
awkward, so these build real answer packets by hand and feed them to the
parser. Each packet below is the wire format from RFC 1035, written out so a
reader can check the bytes against the spec.

The behaviour itself was taken from dnspython, by asking both for the same 15
real lookups before dnspython was removed and requiring identical answers.
"""

from __future__ import annotations

import struct

import pytest

from engine.dnswire import (
    TYPE_CODES,
    DnsError,
    _build_query,
    _parse_answers,
    _read_name,
    reverse_name,
)

QUERY_ID = 0x1234


def _name(label_string: str) -> bytes:
    out = bytearray()
    for label in label_string.rstrip(".").split("."):
        out.append(len(label))
        out += label.encode()
    out.append(0)
    return bytes(out)


def _answer(rdtype: str, rdata: bytes, *, rcode: int = 0, count: int = 1) -> bytes:
    """One answer packet for `example.com`, built the way a resolver sends it."""
    header = struct.pack("!HHHHHH", QUERY_ID, 0x8180 | rcode, 1, count, 0, 0)
    question = _name("example.com") + struct.pack("!HH", TYPE_CODES[rdtype], 1)
    body = b""
    for _ in range(count):
        body += (
            _name("example.com")
            + struct.pack("!HHIH", TYPE_CODES[rdtype], 1, 300, len(rdata))
            + rdata
        )
    return header + question + body


# ── reading each record type ─────────────────────────────────────────────


def test_an_address_record() -> None:
    assert _parse_answers(_answer("A", bytes([93, 184, 216, 34])), "A", QUERY_ID) == [
        "93.184.216.34"
    ]


def test_a_text_record() -> None:
    rdata = bytes([len("v=spf1 -all")]) + b"v=spf1 -all"
    assert _parse_answers(_answer("TXT", rdata), "TXT", QUERY_ID) == ["v=spf1 -all"]


def test_a_long_text_record_arrives_in_pieces_and_joins_with_nothing() -> None:
    """A DKIM key is longer than 255 bytes, so it is published split."""
    first, second = b"k=rsa; p=AAAA", b"BBBBCCCC"
    rdata = bytes([len(first)]) + first + bytes([len(second)]) + second
    assert _parse_answers(_answer("TXT", rdata), "TXT", QUERY_ID) == ["k=rsa; p=AAAABBBBCCCC"]


def test_a_mail_record_keeps_its_preference() -> None:
    rdata = struct.pack("!H", 10) + _name("mx.example.com")
    assert _parse_answers(_answer("MX", rdata), "MX", QUERY_ID) == ["10 mx.example.com"]


@pytest.mark.parametrize("rdtype", ["NS", "PTR", "CNAME"])
def test_a_record_that_is_just_a_name_loses_its_trailing_dot(rdtype: str) -> None:
    assert _parse_answers(_answer(rdtype, _name("target.example.com")), rdtype, QUERY_ID) == [
        "target.example.com"
    ]


def test_every_record_in_the_answer_is_returned() -> None:
    packet = _answer("A", bytes([1, 2, 3, 4]), count=3)
    assert _parse_answers(packet, "A", QUERY_ID) == ["1.2.3.4"] * 3


# ── failures the caller reports differently ──────────────────────────────


def test_a_name_that_does_not_exist() -> None:
    with pytest.raises(DnsError) as caught:
        _parse_answers(_answer("A", b"", rcode=3, count=0), "A", QUERY_ID)
    assert caught.value.category == "nxdomain"


def test_a_name_that_exists_with_no_record_of_that_type() -> None:
    with pytest.raises(DnsError) as caught:
        _parse_answers(_answer("TXT", b"", count=0), "TXT", QUERY_ID)
    assert caught.value.category == "no_answer"


def test_an_answer_to_someone_elses_question_is_refused() -> None:
    """The id guards against an off-path answer arriving first."""
    with pytest.raises(DnsError) as caught:
        _parse_answers(_answer("A", bytes([1, 2, 3, 4])), "A", QUERY_ID + 1)
    assert caught.value.category == "error:AnswerIdMismatch"


def test_a_record_of_another_type_is_not_counted() -> None:
    """Asking for A often returns a CNAME beside it. It is not an A record."""
    header = struct.pack("!HHHHHH", QUERY_ID, 0x8180, 1, 1, 0, 0)
    question = _name("example.com") + struct.pack("!HH", TYPE_CODES["A"], 1)
    cname = (
        _name("example.com")
        + struct.pack("!HHIH", TYPE_CODES["CNAME"], 1, 300, len(_name("other.test")))
        + _name("other.test")
    )
    with pytest.raises(DnsError) as caught:
        _parse_answers(header + question + cname, "A", QUERY_ID)
    assert caught.value.category == "no_answer"


# ── name compression ─────────────────────────────────────────────────────


def test_a_compressed_name_is_followed() -> None:
    data = b"\x00\x00" + _name("example.com") + b"\xc0\x02"
    name, _ = _read_name(data, len(data) - 2)
    assert name == "example.com"


def test_a_pointer_that_does_not_point_backwards_is_refused() -> None:
    """A forward or self pointer is how a malformed answer becomes a loop."""
    data = b"\x00\x00\xc0\x02"
    with pytest.raises(DnsError) as caught:
        _read_name(data, 2)
    assert caught.value.category == "error:CompressionLoop"


# ── the question we send ─────────────────────────────────────────────────


def test_the_query_asks_for_recursion_and_one_question() -> None:
    query = _build_query("example.com", "TXT", QUERY_ID)
    query_id, flags, questions, answers, _, _ = struct.unpack_from("!HHHHHH", query, 0)
    assert (query_id, flags, questions, answers) == (QUERY_ID, 0x0100, 1, 0)
    assert query.endswith(struct.pack("!HH", TYPE_CODES["TXT"], 1))


def test_an_unsupported_type_is_refused_before_any_socket_is_opened() -> None:
    from engine.dnswire import resolve

    with pytest.raises(DnsError) as caught:
        resolve("example.com", "SRV")
    assert caught.value.category == "error:UnsupportedTypeSRV"


# ── reverse names ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("ip", "expected"),
    [
        ("8.8.8.8", "8.8.8.8.in-addr.arpa."),
        ("192.0.2.1", "1.2.0.192.in-addr.arpa."),
        (
            "2001:db8::1",
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
        ),
    ],
)
def test_reverse_name(ip: str, expected: str) -> None:
    assert reverse_name(ip) == expected


def test_something_that_is_not_an_address() -> None:
    with pytest.raises(ValueError):
        reverse_name("not-an-ip")
