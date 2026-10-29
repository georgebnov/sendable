"""The DKIM key size is read with the standard library, exactly.

A published DKIM key is one of two DER shapes. Most senders publish a
SubjectPublicKeyInfo, which is what `openssl rsa -pubout` writes. Strict
RFC 6376 asks for a bare RSAPublicKey. A verifier accepts both, so the audit
must read both, and it must report the real bit count rather than a guess,
because the finding text prints the number.

Every key below was generated with openssl, so these are real records and not
hand-written bytes.
"""

from __future__ import annotations

import pytest

from engine.domain.dns.dkim import _key_bits, _rsa_modulus_bits
from tests.dkim_keys import KEYS


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("spki_1024", 1024),
        ("spki_2048", 2048),
        ("spki_4096", 4096),
        ("bare_1024", 1024),
        ("bare_2048", 2048),
        ("bare_4096", 4096),
    ],
)
def test_reads_the_real_bit_count_from_both_der_shapes(name: str, expected: int) -> None:
    assert _key_bits(KEYS[name]) == expected


@pytest.mark.parametrize("name", ["spki_1024", "bare_4096"])
def test_the_der_reader_agrees_with_the_public_entry_point(name: str) -> None:
    import base64

    der = base64.b64decode(KEYS[name])
    assert _rsa_modulus_bits(der) == _key_bits(KEYS[name])


def test_an_ed25519_key_is_fixed_size() -> None:
    """Ed25519 has one size, so no DER is read for it."""
    assert _key_bits(KEYS["ed25519"], "ed25519") == 256


@pytest.mark.parametrize(
    "value",
    [
        "",
        "not base64 at all !!!",
        "aGVsbG8=",  # valid base64, not DER
        "MAoCAQE=",  # DER, but no modulus to find
    ],
)
def test_a_key_it_cannot_read_reports_nothing(value: str) -> None:
    """A wrong answer is worse than no answer, so an unreadable key is None."""
    assert _key_bits(value) is None
