"""The DKIM record audit: is there a key, is it strong, does it sign enough.

DKIM signs an email with a private key and publishes the matching public key in
DNS at `<selector>._domainkey.<domain>`. The audit reads the signature header to
learn the selector, looks up the key, and grades it. With no signature on the
message it brute-forces the common selectors, which is how a domain-only audit
works.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from engine.domain.dns import dkim
from engine.report import Finding
from tests.conftest import FakeDns

PREFIX = "dkim_record"


def _rsa_key_p_value(bits: int) -> str:
    """The base64 p= tag for a real RSA public key of the given size."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits).public_key()
    der = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(der).decode()


@pytest.fixture(scope="module")
def key_2048() -> str:
    # Generated once per module: RSA keygen is the slowest thing in this file.
    return _rsa_key_p_value(2048)


@pytest.fixture(scope="module")
def key_1024() -> str:
    return _rsa_key_p_value(1024)


def _headers(
    signing_domain: str = "example.com",
    selector: str = "s1",
    h: str = "from:subject",
    bulk: bool = False,
) -> dict[str, list[str]]:
    out = {
        "dkim-signature": [
            f"v=1; a=rsa-sha256; c=relaxed/relaxed; d={signing_domain}; s={selector}; "
            f"h={h}; bh=abc=; b=def="
        ]
    }
    if bulk:
        # The unsubscribe-coverage check only runs when the message carries these
        # headers. With no List-Unsubscribe there is nothing for h= to cover.
        out["list-unsubscribe"] = ["<https://example.com/u/1>"]
        out["list-unsubscribe-post"] = ["List-Unsubscribe=One-Click"]
    return out


def _by(findings: list[Finding], suffix: str) -> Finding | None:
    for f in findings:
        if f.check == f"{PREFIX}.{suffix}":
            return f
    return None


# ── key size, the reason cryptography is a dependency ──────────────────────


async def test_a_2048_bit_key_passes(dns: FakeDns, key_2048: str) -> None:
    dns.set("s1._domainkey.example.com", "TXT", f"v=DKIM1; k=rsa; p={key_2048}")
    findings = await dkim.run("example.com", _headers())
    bits = _by(findings, "key_bits")
    assert bits is not None
    assert bits.passed is True
    assert "2048" in bits.message


async def test_a_1024_bit_key_is_reported_as_weak(dns: FakeDns, key_1024: str) -> None:
    # 1024-bit RSA is below the floor. Several receivers now discount or ignore
    # a signature made with one, so the signature stops earning reputation.
    dns.set("s1._domainkey.example.com", "TXT", f"v=DKIM1; k=rsa; p={key_1024}")
    findings = await dkim.run("example.com", _headers())
    bits = _by(findings, "key_bits")
    assert bits is not None
    assert bits.passed is False


async def test_an_ed25519_key_is_accepted_at_its_fixed_size(dns: FakeDns) -> None:
    # Ed25519 is always 256-bit. Grading it against an RSA floor would report a
    # strong modern key as weak.
    dns.set("s1._domainkey.example.com", "TXT", "v=DKIM1; k=ed25519; p=" + "A" * 43 + "=")
    findings = await dkim.run("example.com", _headers())
    bits = _by(findings, "key_bits")
    assert bits is not None
    assert bits.passed is True


# ── published or not ───────────────────────────────────────────────────────


async def test_a_missing_record_for_a_named_selector_is_reported(dns: FakeDns) -> None:
    # The message says it was signed with s1, but no key is published there, so
    # every receiver will fail the signature.
    findings = await dkim.run("example.com", _headers())
    published = _by(findings, "published")
    assert published is not None
    assert published.passed is False


async def test_no_signature_triggers_a_selector_scan(dns: FakeDns) -> None:
    findings = await dkim.run("example.com", {})
    published = _by(findings, "published")
    assert published is not None
    assert published.passed is False
    assert published.details["selectors_tried"], "the scan must report what it tried"
    assert len(dns.asked) > 1, "a scan asks for more than one selector"


async def test_a_selector_scan_finds_a_key_at_a_common_selector(
    dns: FakeDns, key_2048: str
) -> None:
    # A domain audit with no email to hand still works when the sender uses a
    # standard selector, which most providers do.
    dns.set("google._domainkey.example.com", "TXT", f"v=DKIM1; k=rsa; p={key_2048}")
    findings = await dkim.run("example.com", {})
    published = _by(findings, "published")
    assert published is not None
    assert published.passed is True


# ── record contents ────────────────────────────────────────────────────────


async def test_an_empty_p_tag_means_a_revoked_key(dns: FakeDns) -> None:
    # p= with no value is how RFC 6376 revokes a key. A message still signed
    # with it cannot verify.
    dns.set("s1._domainkey.example.com", "TXT", "v=DKIM1; k=rsa; p=")
    findings = await dkim.run("example.com", _headers())
    key = _by(findings, "public_key")
    assert key is not None
    assert key.passed is False


async def test_relaxed_canonicalization_passes(dns: FakeDns, key_2048: str) -> None:
    dns.set("s1._domainkey.example.com", "TXT", f"v=DKIM1; k=rsa; p={key_2048}")
    findings = await dkim.run("example.com", _headers())
    canon = _by(findings, "canonicalization")
    assert canon is not None
    assert canon.passed is True


async def test_simple_canonicalization_is_reported(dns: FakeDns, key_2048: str) -> None:
    # simple/simple breaks the signature when any relay rewrites whitespace,
    # which is common, so the signature fails for reasons the sender cannot see.
    dns.set("s1._domainkey.example.com", "TXT", f"v=DKIM1; k=rsa; p={key_2048}")
    headers = {
        "dkim-signature": [
            "v=1; a=rsa-sha256; c=simple/simple; d=example.com; s=s1; "
            "h=from:subject; bh=abc=; b=def="
        ]
    }
    findings = await dkim.run("example.com", headers)
    canon = _by(findings, "canonicalization")
    assert canon is not None
    assert canon.passed is False


async def test_an_unsigned_unsubscribe_header_is_reported(dns: FakeDns, key_2048: str) -> None:
    # If List-Unsubscribe is outside h=, a relay can add or change it without
    # breaking the signature, so the one-click guarantee is not actually signed.
    dns.set("s1._domainkey.example.com", "TXT", f"v=DKIM1; k=rsa; p={key_2048}")
    findings = await dkim.run("example.com", _headers(h="from:subject", bulk=True))
    cov = _by(findings, "h_coverage_unsubscribe")
    assert cov is not None
    assert cov.passed is False


async def test_a_signed_unsubscribe_header_passes(dns: FakeDns, key_2048: str) -> None:
    dns.set("s1._domainkey.example.com", "TXT", f"v=DKIM1; k=rsa; p={key_2048}")
    findings = await dkim.run(
        "example.com",
        _headers(h="from:subject:list-unsubscribe:list-unsubscribe-post", bulk=True),
    )
    cov = _by(findings, "h_coverage_unsubscribe")
    assert cov is not None
    assert cov.passed is True


# ── third-party signing ────────────────────────────────────────────────────


async def test_third_party_only_signing_is_named_not_called_unconfigured(
    dns: FakeDns,
) -> None:
    # The message IS DKIM-signed, by the provider's key on the provider's domain.
    # Telling this sender "DKIM is not configured" is wrong and sends them to fix
    # something that is working. The report must say what is actually true: the
    # provider signs, and their own domain publishes no key.
    findings = await dkim.run("example.com", _headers(signing_domain="sendgrid.info"))
    published = _by(findings, "published")
    assert published is not None
    assert published.passed is False
    assert "not configured" not in published.message.lower(), (
        "the mail is signed; claiming DKIM is unconfigured is false"
    )
    assert "sendgrid.info" in str(published.details) + published.message, (
        "the report must name the provider that signs, so the sender knows where to look"
    )


async def test_a_third_party_signature_alongside_your_own_is_reported_separately(
    dns: FakeDns, key_2048: str
) -> None:
    # Two signatures: the sender's own and the provider's. The provider key is
    # not under the sender's control, so it must not drag their record score.
    dns.set("s1._domainkey.example.com", "TXT", f"v=DKIM1; k=rsa; p={key_2048}")
    headers = _headers()
    headers["dkim-signature"].append(
        "v=1; a=rsa-sha256; c=relaxed/relaxed; d=sendgrid.info; s=smtpapi; "
        "h=from:subject; bh=abc=; b=def="
    )
    findings = await dkim.run("example.com", headers)
    third = _by(findings, "third_party_signatures")
    assert third is not None
    assert "sendgrid.info" in str(third.details) + third.message


# ── the check never raises ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    "record",
    [
        "v=DKIM1",
        "not a dkim record at all",
        "v=DKIM1; k=rsa; p=!!!not-base64!!!",
        "v=DKIM1; k=unknown-algorithm; p=AAAA",
        "",
    ],
    ids=["no-tags", "garbage", "bad-base64", "unknown-alg", "empty"],
)
async def test_a_malformed_record_does_not_raise(dns: FakeDns, record: str) -> None:
    dns.set("s1._domainkey.example.com", "TXT", record)
    findings = await dkim.run("example.com", _headers())
    assert findings, "a malformed record still deserves a finding"
