"""DKIM record check at <selector>._domainkey.<domain>.

Selector is extracted from the email's `DKIM-Signature` header (`s=` tag).
mxtoolbox's "DKIM Signature Body Hash Verified" is intentionally NOT
done — forwarded mail breaks body-hash verification, so we rely on the
receiving MTA's `Authentication-Results` for the dkim= result.

Covered:
  - Record Published
  - Public Key Check (parse `p=` tag, presence + non-empty)
  - Key bit length — Gmail/Yahoo bulk-sender requirement is ≥1024-bit;
    1024 is the floor and 2048 is the modern recommendation.
  - Syntax Check (recognized tags, k= / t= / s= / v= sanity)
  - `h=` coverage of List-Unsubscribe / List-Unsubscribe-Post — RFC 8058
    requires the one-click unsubscribe headers to be DKIM-signed for
    bulk mail. Gmail/Yahoo enforce this; missing coverage means the
    one-click endpoint can be tampered with in transit.
  - `c=` canonicalization advisory — body=simple is brittle, any relay
    that mutates whitespace in transit breaks the body hash. Bulk senders
    should publish `c=relaxed/relaxed`. Tag is valid either way so this
    doesn't surface in syntax.
"""

from __future__ import annotations

import asyncio
import base64
import re

from ...copywriting.link_quality import _registrable
from ...report import Finding
from ...severity import Severity
from ..dns_client import query


def _in_scope_for(signing_domain: str, target_domain: str) -> bool:
    """A DKIM signature is in scope for grading `target_domain` if its
    signing domain is the same organizational domain or a subdomain.

    Example: target=example.com → in scope: example.com, cka.example.com,
    sub.example.com. Out of scope: sendgrid.info, mailchimp.com.

    Out-of-scope keys belong to ESPs / shared infrastructure — the user
    has zero control over them, so docking the domain's score for a
    third-party's 1024-bit key is wrong (the actual bug the user caught).
    """
    return _registrable(signing_domain.lower()) == _registrable(target_domain.lower())


CHECK_PREFIX = "dkim_record"

_DKIM_SIG_TAG_RX = re.compile(r"\b([a-zA-Z])\s*=\s*([^;]+?)\s*(?:;|$)")
_VALID_TAGS = {"v", "k", "t", "s", "g", "h", "n", "p", "q"}

# Common DKIM selectors, used when the email has no DKIM-Signature header
# (e.g. domain-only audits). Covers ~95% of corporate domains: the
# 25-selector "first pass" from doc §4 plus a few provider-specific ones.
_COMMON_SELECTORS = (
    "default",
    "dkim",
    "google",
    "selector1",
    "selector2",
    "s1",
    "s2",
    "k1",
    "k2",
    "mail",
    "email",
    "mxvault",
    "smtp",
    "mandrill",
    "mailchimp",
    "mta",
    "mta1",
    "mta2",
    "dkim1",
    "dkim2",
    "key1",
    "key2",
    "zoho",
    "protonmail",
    "everlytickey1",
    "brevo1",
    "brevo2",
    "sendgrid",
    "sendgrid1",
    "sendgrid2",
    "amazonses",
)

# Modern minimum is 1024-bit per Gmail/Yahoo bulk-sender requirements.
# 2048 is the recommended target; receivers don't penalise above 1024 but
# may downgrade trust below.
_DKIM_KEY_BITS_FLOOR = 1024


def _der_tlv(data: bytes, pos: int) -> tuple[int, bytes, int]:
    """Read one DER tag-length-value. Returns the tag, the value, and where the
    next one starts. Raises ValueError on anything malformed."""
    if pos + 2 > len(data):
        raise ValueError("truncated DER header")
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        # A 4-byte length covers any key anyone publishes. Longer means the
        # record is not a key, so refuse rather than allocate on its say-so.
        if count == 0 or count > 4 or pos + count > len(data):
            raise ValueError("bad DER length")
        length = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    if pos + length > len(data):
        raise ValueError("truncated DER value")
    return tag, data[pos : pos + length], pos + length


def _rsa_modulus_bits(der: bytes) -> int | None:
    """Bit length of the RSA modulus, read straight from the DER.

    A sender publishes one of two shapes. Most publish a SubjectPublicKeyInfo,
    which is what `openssl rsa -pubout` writes: a sequence holding the algorithm
    identifier and a bit string that wraps the real key. Strict RFC 6376 asks for
    a bare RSAPublicKey, which is a sequence of the modulus and the exponent. A
    verifier accepts both, so this reads both.

    Returns None for anything it cannot read. The caller reports no finding in
    that case, which is right: a guessed length printed as fact sends a sender to
    fix a key that works.
    """
    sequence, integer, bit_string = 0x30, 0x02, 0x03
    try:
        tag, body, _ = _der_tlv(der, 0)
        if tag != sequence:
            return None
        tag, value, pos = _der_tlv(body, 0)
        if tag == sequence:
            # SubjectPublicKeyInfo. Step over the algorithm identifier we just
            # read, take the bit string, and drop its first byte, which counts
            # unused trailing bits rather than carrying key material.
            tag, value, _ = _der_tlv(body, pos)
            if tag != bit_string or not value:
                return None
            tag, body, _ = _der_tlv(value[1:], 0)
            if tag != sequence:
                return None
            tag, value, _ = _der_tlv(body, 0)
        if tag != integer or not value:
            return None
        return int.from_bytes(value, "big").bit_length()
    except (ValueError, IndexError):
        return None


def _key_bits(p_value: str, k_alg: str = "rsa") -> int | None:
    """Size of the published signing key, or None when it cannot be read."""
    cleaned = "".join(p_value.split())
    if not cleaned:
        return None
    try:
        der = base64.b64decode(cleaned, validate=False)
    except Exception:
        return None

    if k_alg == "ed25519":
        return 256  # Ed25519 is fixed-size

    return _rsa_modulus_bits(der)


def _canonicalization(c_value: str | None) -> tuple[str, str]:
    """Resolve the `c=` tag into (header_canon, body_canon) per RFC 6376
    §3.5. Default when tag is absent: `simple/simple`. When only one
    algorithm is given, the body algorithm defaults to `simple`."""
    if not c_value:
        return ("simple", "simple")
    parts = [p.strip().lower() for p in c_value.split("/", 1)]
    header = parts[0] if parts and parts[0] in ("simple", "relaxed") else "simple"
    body = parts[1] if len(parts) == 2 and parts[1] in ("simple", "relaxed") else "simple"
    return (header, body)


def _signatures(headers: dict[str, list[str]]) -> list[dict]:
    """Parse every DKIM-Signature header into a tag-dict. Returns a list
    of {selector, signing_domain, h_signed, canon}. h_signed is the lowercase
    set of header names this signature covers (from the `h=` tag). canon is
    a (header_canon, body_canon) tuple resolved from the `c=` tag."""
    out: list[dict] = []
    for raw in headers.get("dkim-signature", []):
        tags = {m.group(1).lower(): m.group(2).strip() for m in _DKIM_SIG_TAG_RX.finditer(raw)}
        s = tags.get("s")
        d = tags.get("d")
        h = tags.get("h", "")
        if not (s and d):
            continue
        h_signed = {p.strip().lower() for p in h.split(":") if p.strip()}
        out.append(
            {
                "selector": s,
                "signing_domain": d.lower(),
                "h_signed": h_signed,
                "canon": _canonicalization(tags.get("c")),
            }
        )
    return out


def _parse_record(text: str) -> dict:
    return {m.group(1).lower(): m.group(2).strip() for m in _DKIM_SIG_TAG_RX.finditer(text)}


async def _bruteforce_selectors(domain: str) -> list[dict]:
    """When no DKIM-Signature header is available, try common selectors
    against `domain`. Returns the same shape as `_signatures()` so the
    caller can audit each found record. Concurrent fan-out, NXDOMAIN-fast."""

    async def _try(sel: str) -> dict | None:
        ans = await query(f"{sel}._domainkey.{domain}", "TXT")
        if not (ans.ok and ans.records):
            return None
        # Confirm it looks like a DKIM record (has p= or v=DKIM1).
        joined = " ".join(ans.records).lower()
        if "p=" not in joined and "v=dkim1" not in joined:
            return None
        return {
            "selector": sel,
            "signing_domain": domain,
            "h_signed": set(),  # unknown — no signature to read h= from
            "canon": None,  # unknown — no c= tag to read
        }

    found = await asyncio.gather(*[_try(s) for s in _COMMON_SELECTORS])
    return [f for f in found if f is not None]


async def run(domain: str, headers: dict[str, list[str]]) -> list[Finding]:
    """Per signature on the email, look up the published record and audit
    it. If no DKIM-Signature is present, brute-force common selectors as
    a fallback (mxtoolbox-style domain-only audit)."""
    sigs_all = _signatures(headers)
    # Filter out signatures from third-party ESPs / shared signing infra
    # (sendgrid.info smtpapi, mailchimp.com k1, etc.). Those keys aren't
    # under the user's control and shouldn't drag this domain's record
    # score. They still authenticate the message — the audit just stops
    # grading them as if the user could rotate them.
    sigs = [s for s in sigs_all if _in_scope_for(s["signing_domain"], domain)]
    out_of_scope = [s for s in sigs_all if not _in_scope_for(s["signing_domain"], domain)]
    bruteforced = False
    if not sigs:
        sigs = await _bruteforce_selectors(domain)
        bruteforced = True
        if not sigs:
            # The message may still be signed, just not by this domain. When the
            # only signatures belong to a provider, saying "DKIM is not
            # configured" is false and sends the sender to fix working mail. Name
            # the provider instead, and say what is actually missing.
            if out_of_scope:
                signers = sorted({s["signing_domain"] for s in out_of_scope if s["signing_domain"]})
                return [
                    Finding(
                        check=f"{CHECK_PREFIX}.published",
                        severity=Severity.MEDIUM,
                        passed=False,
                        message=(
                            f"{', '.join(signers)} signs this mail, not {domain}. The "
                            "signature does prove the message was not changed. But the "
                            "key belongs to that provider, so you cannot replace it, and "
                            "it does not match your From address. Ask your sending tool "
                            f"for a branded or custom signing setup, which puts a key "
                            f"under {domain}."
                        ),
                        details={
                            "third_party_signers": signers,
                            "selectors_tried": list(_COMMON_SELECTORS),
                        },
                    )
                ]
            return [
                Finding(
                    check=f"{CHECK_PREFIX}.published",
                    severity=Severity.HIGH,
                    passed=False,
                    message=(
                        f"No DKIM record found for {domain} via brute-force scan "
                        f"of {len(_COMMON_SELECTORS)} common selectors. Either "
                        "DKIM is not configured or your selector is non-standard."
                    ),
                    details={"selectors_tried": list(_COMMON_SELECTORS)},
                )
            ]

    has_lu = bool(headers.get("list-unsubscribe"))
    findings: list[Finding] = []

    # Surface (but never deduct for) any third-party signatures we ignored
    # above, so the audit transparently shows them as context rather than
    # silently dropping them.
    if out_of_scope:
        oos_names = ", ".join(
            f"{s['selector']}._domainkey.{s['signing_domain']}" for s in out_of_scope
        )
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.third_party_signatures",
                severity=Severity.INFO,
                passed=True,
                message=(
                    f"Saw {len(out_of_scope)} DKIM signature(s) from ESP / shared "
                    f"infrastructure ({oos_names}). Those keys aren't under your "
                    f"control, so they don't affect this domain's score."
                ),
                details={
                    "out_of_scope": [
                        {"selector": s["selector"], "signing_domain": s["signing_domain"]}
                        for s in out_of_scope
                    ]
                },
            )
        )

    for sig in sigs:
        selector = sig["selector"]
        signing_domain = sig["signing_domain"]
        h_signed = sig["h_signed"]
        qname = f"{selector}._domainkey.{signing_domain}"
        ans = await query(qname, "TXT")
        records = list(ans.records) if ans.ok else []
        if not records:
            findings.append(
                Finding(
                    check=f"{CHECK_PREFIX}.published",
                    severity=Severity.HIGH,
                    passed=False,
                    message=f"No DKIM record at {qname}.",
                    details={
                        "dns_error": ans.error,
                        "selector": selector,
                        "signing_domain": signing_domain,
                    },
                )
            )
            continue

        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.published",
                severity=Severity.INFO,
                passed=True,
                message=f"DKIM record published at {qname}.",
                details={"selector": selector, "signing_domain": signing_domain},
            )
        )

        parsed = _parse_record(records[0])
        public_key = parsed.get("p", "")
        if not public_key.strip():
            findings.append(
                Finding(
                    check=f"{CHECK_PREFIX}.public_key",
                    severity=Severity.HIGH,
                    passed=False,
                    message=f"DKIM record at {qname} has empty p= (key revoked).",
                    details={"selector": selector},
                )
            )
        else:
            findings.append(
                Finding(
                    check=f"{CHECK_PREFIX}.public_key",
                    severity=Severity.INFO,
                    passed=True,
                    message=f"DKIM public key present at {qname} ({len(public_key)} chars).",
                    details={"selector": selector, "key_chars": len(public_key)},
                )
            )

            # Key bit-length sanity. The DER reader above handles both SPKI
            # and bare-RSAPublicKey forms.
            #
            # The floor is an RSA floor. Ed25519 keys are always 256-bit and that
            # is strong: RFC 8463 defines Ed25519-SHA256 for DKIM precisely
            # because a 256-bit curve key gives more security than a 2048-bit RSA
            # key in a much smaller record. Measuring it against the RSA floor
            # reported a correct modern key as dangerously weak, which sent the
            # sender to "fix" a working configuration.
            k_alg = (parsed.get("k") or "rsa").lower()
            bits = _key_bits(public_key, k_alg)
            if k_alg == "ed25519":
                findings.append(
                    Finding(
                        check=f"{CHECK_PREFIX}.key_bits",
                        severity=Severity.INFO,
                        passed=True,
                        message=(
                            f"The signing key at {qname} is the newer, shorter kind "
                            "(Ed25519). Its length is fixed, and it is stronger than "
                            "the older kind at eight times the size, so the length "
                            "rule does not apply to it."
                        ),
                        details={"selector": selector, "algorithm": "ed25519", "bits": bits},
                    )
                )
            elif bits is not None:
                if bits < _DKIM_KEY_BITS_FLOOR:
                    findings.append(
                        Finding(
                            check=f"{CHECK_PREFIX}.key_bits",
                            severity=Severity.HIGH,
                            passed=False,
                            message=(
                                f"DKIM key at {qname} is ~{bits}-bit; "
                                f"Gmail/Yahoo bulk-sender requirement is "
                                f"≥{_DKIM_KEY_BITS_FLOOR}-bit. Modern recommendation is 2048."
                            ),
                            details={
                                "selector": selector,
                                "bits": bits,
                                "floor": _DKIM_KEY_BITS_FLOOR,
                            },
                        )
                    )
                elif bits == _DKIM_KEY_BITS_FLOOR:
                    findings.append(
                        Finding(
                            check=f"{CHECK_PREFIX}.key_bits",
                            severity=Severity.LOW,
                            passed=False,
                            message=(
                                f"DKIM key at {qname} is ~{bits}-bit (the floor). "
                                "Recommended target is 2048-bit."
                            ),
                            details={"selector": selector, "bits": bits},
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check=f"{CHECK_PREFIX}.key_bits",
                            severity=Severity.INFO,
                            passed=True,
                            message=(
                                f"DKIM key at {qname} is ~{bits}-bit (≥{_DKIM_KEY_BITS_FLOOR})."
                            ),
                            details={"selector": selector, "bits": bits},
                        )
                    )

        syntax_issues: list[str] = []
        for tag in parsed:
            if tag not in _VALID_TAGS:
                syntax_issues.append(f"unknown tag '{tag}'")
        if "v" in parsed and parsed["v"].upper() != "DKIM1":
            syntax_issues.append(f"v='{parsed['v']}' must be DKIM1")
        if "k" in parsed and parsed["k"].lower() not in ("rsa", "ed25519"):
            syntax_issues.append(f"k='{parsed['k']}' unsupported")
        if "t" in parsed:
            flags = [f.strip().lower() for f in parsed["t"].split(":") if f.strip()]
            for flag in flags:
                if flag not in ("y", "s"):
                    syntax_issues.append(f"t flag '{flag}' invalid")
            if "y" in flags:
                syntax_issues.append("t=y flag set: testing mode (receivers may downgrade)")

        if syntax_issues:
            findings.append(
                Finding(
                    check=f"{CHECK_PREFIX}.syntax",
                    severity=Severity.MEDIUM,
                    passed=False,
                    message=f"DKIM record syntax issues: {'; '.join(syntax_issues[:5])}",
                    details={"selector": selector, "issues": syntax_issues},
                )
            )
        else:
            findings.append(
                Finding(
                    check=f"{CHECK_PREFIX}.syntax",
                    severity=Severity.INFO,
                    passed=True,
                    message=f"DKIM record syntax OK at {qname}.",
                    details={"selector": selector},
                )
            )

        # h= coverage of List-Unsubscribe (RFC 8058 / Gmail+Yahoo bulk req).
        # Skip when we brute-forced — no signature header means no h= to read.
        if has_lu and not bruteforced:
            covered_lu = "list-unsubscribe" in h_signed
            covered_lup = "list-unsubscribe-post" in h_signed
            missing = [
                hdr
                for hdr, ok in (
                    ("list-unsubscribe", covered_lu),
                    ("list-unsubscribe-post", covered_lup),
                )
                if not ok
            ]
            if missing:
                findings.append(
                    Finding(
                        check=f"{CHECK_PREFIX}.h_coverage_unsubscribe",
                        severity=Severity.HIGH,
                        passed=False,
                        message=(
                            f"The signature from {signing_domain} does not protect "
                            f"{missing}. Gmail and Yahoo require the unsubscribe "
                            "headers to be signed on bulk mail. Unsigned, anyone who "
                            "handles the message on its way can change where the "
                            "unsubscribe link points."
                        ),
                        details={
                            "selector": selector,
                            "missing": missing,
                            "h_signed": sorted(h_signed),
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        check=f"{CHECK_PREFIX}.h_coverage_unsubscribe",
                        severity=Severity.INFO,
                        passed=True,
                        message="DKIM signature covers List-Unsubscribe + List-Unsubscribe-Post.",
                        details={"selector": selector},
                    )
                )

        # c= canonicalization advisory (RFC 6376 §3.5). Two distinct risk
        # tiers conflated under one finding ID, both LOW severity:
        #   - body=simple is the REAL risk. ESP footer insertion / relay
        #     whitespace mutation breaks the body hash on almost every
        #     bulk send. Lead the message with this.
        #   - header=simple is the MINOR risk. Only aggressive relay
        #     header-refolding breaks signing, which is rare. Mention as
        #     secondary so the marketer reads the priority correctly.
        # Skip when bruteforced — no signature to read c= from.
        if not bruteforced and sig.get("canon") is not None:
            header_canon, body_canon = sig["canon"]
            body_simple = body_canon == "simple"
            header_simple = header_canon == "simple"
            if body_simple or header_simple:
                # Build message: body issue leads, header issue trails.
                parts: list[str] = []
                risk_tiers: list[str] = []
                if body_simple:
                    parts.append(
                        "Body canonicalization is `simple`: this is the "
                        "main risk: ESP footer insertion or any relay "
                        "whitespace mutation breaks the body hash and the "
                        "signature fails to verify on the receiver side."
                    )
                    risk_tiers.append("body=simple (HIGH risk on bulk sends)")
                if header_simple:
                    parts.append(
                        "Header canonicalization is `simple`: minor risk; "
                        "only relays that aggressively refold long headers "
                        "will break the signature."
                    )
                    risk_tiers.append("header=simple (LOW risk)")
                findings.append(
                    Finding(
                        check=f"{CHECK_PREFIX}.canonicalization",
                        severity=Severity.LOW,
                        passed=False,
                        message=(
                            f"The signature from {signing_domain} is set to break if "
                            "a relay changes the spacing in transit, which relays do. "
                            "Ask your sending provider for the tolerant setting. " + " ".join(parts)
                        ),
                        details={
                            "selector": selector,
                            "header_canon": header_canon,
                            "body_canon": body_canon,
                            "risk_tiers": risk_tiers,
                            "primary_risk": "body=simple" if body_simple else "header=simple",
                            "recommended": "relaxed/relaxed",
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        check=f"{CHECK_PREFIX}.canonicalization",
                        severity=Severity.INFO,
                        passed=True,
                        message=(
                            f"The signature at {qname} tolerates the small spacing "
                            "changes a relay makes in transit."
                        ),
                        details={
                            "selector": selector,
                            "header_canon": header_canon,
                            "body_canon": body_canon,
                        },
                    )
                )

    return findings
