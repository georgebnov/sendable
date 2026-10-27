"""DMARC alignment + Return-Path / Reply-To alignment checks.

The receiver's `Authentication-Results` header reports DMARC pass/fail —
but it doesn't tell us *which* alignment carried the day. A message can
show `dmarc=pass` because DKIM's `d=` aligns even when SPF's MailFrom
domain points to a third-party bounce host. That's fine for delivery
*today* but brittle: rotate DKIM keys, change ESP, and the only thing
keeping you off `p=quarantine` quietly disappears.

What we check:

  - `auth.dmarc_alignment_dkim` — DKIM-Signature `d=` registrable-domain
    must equal From organizational domain (relaxed) for DKIM-aligned DMARC.
  - `auth.dmarc_alignment_spf`  — Return-Path (RFC5321.MailFrom)
    registrable-domain must equal From org-domain (relaxed) for SPF-aligned
    DMARC. Most ESPs use bounce subdomains under the sender's own apex
    (e.g. `bounce.example.com`) which still aligns under relaxed.
  - `auth.dmarc_alignment_overall` — at least one of the two must pass for
    DMARC to be aligned. Even if dmarc=pass today, a FAIL here means a
    config change at the ESP could flip you tomorrow.
  - `auth.reply_to_alignment` — Reply-To registrable-domain ≠ From
    org-domain is a Promotions/phishing-shape signal.
  - `auth.reply_to_monitored` — effective reply address (Reply-To if
    present else From) is not a `noreply@` / `donotreply@` mailbox.
    Microsoft sender guidance: the From or Reply-To should be valid,
    reflect the true sending domain, and be able to receive replies.
    Unmonitored mailboxes are a soft Promotions signal.

Doc tier: §1 (DMARC alignment), §9 (header alignment).
"""

from __future__ import annotations

import re
from email.utils import getaddresses, parseaddr

from ...copywriting.link_quality import _registrable
from ...parse import ParsedEmail
from ...report import Finding
from ...severity import Severity

CHECK_PREFIX = "auth"

_DKIM_D_RX = re.compile(r"\bd\s*=\s*([^;\s]+)", re.IGNORECASE)

# Mailboxes that explicitly cannot receive replies. Lowercase, exact-match
# on local-part. Microsoft guidance: From / Reply-To should be a valid,
# monitored address.
_UNMONITORED_LOCALPARTS = frozenset(
    {
        "noreply",
        "no-reply",
        "no_reply",
        "donotreply",
        "do-not-reply",
        "do_not_reply",
        "donot-reply",
        "no.reply",
        "do.not.reply",
    }
)


def _from_org_domain(parsed: ParsedEmail) -> str | None:
    if not parsed.from_addr:
        return None
    _, addr = parseaddr(parsed.from_addr)
    if "@" not in addr:
        return None
    return _registrable(addr.split("@", 1)[1].lower())


def _return_path_domain(parsed: ParsedEmail) -> str | None:
    """Return-Path is set by the final receiving MTA from the SMTP
    `MAIL FROM:` envelope. Falls back to None for forwarded/rewritten mail
    that strips it."""
    rp = parsed.headers.get("return-path", [])
    if not rp:
        return None
    _, addr = parseaddr(rp[0])
    if "@" not in addr:
        return None
    return _registrable(addr.split("@", 1)[1].lower())


def _dkim_signing_domains(parsed: ParsedEmail) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in parsed.headers.get("dkim-signature", []):
        m = _DKIM_D_RX.search(raw)
        if not m:
            continue
        reg = _registrable(m.group(1).lower().strip())
        if reg and reg not in seen:
            seen.add(reg)
            out.append(reg)
    return out


def _reply_to_domains(parsed: ParsedEmail) -> list[str]:
    rt = parsed.headers.get("reply-to", [])
    if not rt:
        return []
    addrs = getaddresses(rt)
    out: list[str] = []
    for _, addr in addrs:
        if "@" in addr:
            reg = _registrable(addr.split("@", 1)[1].lower())
            if reg:
                out.append(reg)
    return out


def _effective_reply_localparts(parsed: ParsedEmail) -> tuple[str, list[str]]:
    """Return (source, localparts). `source` is 'reply-to' when a Reply-To
    header is present (replies route there), else 'from' (replies route to
    From by default). Localparts are lowercased, before '@'."""
    rt = parsed.headers.get("reply-to", [])
    if rt:
        addrs = getaddresses(rt)
        source = "reply-to"
    else:
        addrs = getaddresses([parsed.from_addr or ""])
        source = "from"
    locals_: list[str] = []
    for _, addr in addrs:
        if "@" in addr:
            local = addr.split("@", 1)[0].lower().strip()
            if local:
                locals_.append(local)
    return source, locals_


async def run(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    from_org = _from_org_domain(email)

    if not from_org:
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.dmarc_alignment_overall",
                severity=Severity.INFO,
                passed=False,
                message="No From: address. Alignment cannot be evaluated.",
            )
        )
        return findings

    # ─── DKIM alignment (relaxed) ────────────────────────────────────
    dkim_domains = _dkim_signing_domains(email)
    dkim_aligned = from_org in dkim_domains if dkim_domains else False

    if not dkim_domains:
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.dmarc_alignment_dkim",
                severity=Severity.MEDIUM,
                passed=False,
                message=(
                    "No DKIM-Signature header on the message. DKIM cannot align "
                    f"with From organizational domain ({from_org})."
                ),
                details={"from_org": from_org},
            )
        )
    elif dkim_aligned:
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.dmarc_alignment_dkim",
                severity=Severity.INFO,
                passed=True,
                message=(
                    f"DKIM aligned: signing domain {from_org} matches From "
                    "organizational domain (relaxed)."
                ),
                details={"from_org": from_org, "dkim_d": dkim_domains},
            )
        )
    else:
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.dmarc_alignment_dkim",
                severity=Severity.HIGH,
                passed=False,
                message=(
                    f"DKIM not aligned: signed by {dkim_domains} but From "
                    f"organizational domain is {from_org}. Receivers will not "
                    "credit DKIM toward DMARC alignment."
                ),
                details={"from_org": from_org, "dkim_d": dkim_domains},
            )
        )

    # ─── SPF alignment (relaxed, via Return-Path) ────────────────────
    return_path_org = _return_path_domain(email)
    if return_path_org is None:
        spf_aligned = False
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.dmarc_alignment_spf",
                severity=Severity.LOW,
                passed=False,
                message=(
                    "No Return-Path header. SPF alignment cannot be evaluated. "
                    "(May be stripped by forwarding; not necessarily an issue.)"
                ),
                details={"from_org": from_org},
            )
        )
    elif return_path_org == from_org:
        spf_aligned = True
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.dmarc_alignment_spf",
                severity=Severity.INFO,
                passed=True,
                message=(
                    f"SPF aligned: Return-Path domain {return_path_org} matches "
                    "From organizational domain (relaxed)."
                ),
                details={"from_org": from_org, "return_path_org": return_path_org},
            )
        )
    else:
        spf_aligned = False
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.dmarc_alignment_spf",
                severity=Severity.MEDIUM,
                passed=False,
                message=(
                    f"SPF not aligned: Return-Path domain {return_path_org} differs "
                    f"from From organizational domain {from_org}. Receivers check SPF "
                    "against the envelope sender, so your apex SPF record is never read "
                    "for this mail. Ask your ESP to move the bounce domain onto a "
                    "subdomain of yours. Do not add the ESP to your apex SPF record, "
                    "because that changes nothing."
                ),
                details={"from_org": from_org, "return_path_org": return_path_org},
            )
        )

    # ─── Overall DMARC alignment ─────────────────────────────────────
    if dkim_aligned or spf_aligned:
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.dmarc_alignment_overall",
                severity=Severity.INFO,
                passed=True,
                message=(
                    f"DMARC alignment OK ({'DKIM' if dkim_aligned else ''}"
                    f"{' + ' if dkim_aligned and spf_aligned else ''}"
                    f"{'SPF' if spf_aligned else ''})."
                ),
                details={
                    "dkim_aligned": dkim_aligned,
                    "spf_aligned": spf_aligned,
                    "from_org": from_org,
                },
            )
        )
    else:
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.dmarc_alignment_overall",
                severity=Severity.CRITICAL,
                passed=False,
                message=(
                    f"Neither DKIM nor SPF aligns with From organizational domain "
                    f"({from_org}). DMARC will fail alignment regardless of "
                    "individual SPF/DKIM pass results. Gmail returns 5.7.26, "
                    "Microsoft 5.7.509."
                ),
                details={
                    "from_org": from_org,
                    "dkim_d": dkim_domains,
                    "return_path_org": return_path_org,
                },
            )
        )

    # ─── Reply-To divergence ─────────────────────────────────────────
    reply_to_domains = _reply_to_domains(email)
    if not reply_to_domains:
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.reply_to_alignment",
                severity=Severity.INFO,
                passed=True,
                message="No Reply-To header: replies go to From: (default behaviour).",
            )
        )
    elif from_org in reply_to_domains:
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.reply_to_alignment",
                severity=Severity.INFO,
                passed=True,
                message=f"Reply-To organizational domain matches From ({from_org}).",
            )
        )
    else:
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.reply_to_alignment",
                severity=Severity.MEDIUM,
                passed=False,
                message=(
                    f"Reply-To domain(s) {reply_to_domains} differ from From "
                    f"organizational domain ({from_org}). Anti-phishing systems "
                    "treat divergence as suspicious; weights toward Promotions."
                ),
                details={"from_org": from_org, "reply_to_orgs": reply_to_domains},
            )
        )

    # ─── Reply-To monitored (noreply@ advisory) ──────────────────────
    # Microsoft sender guidance: From or Reply-To should be a valid,
    # monitored address able to receive replies. `noreply@` and friends
    # are soft Promotions signals and discourage two-way engagement —
    # engagement is a deliverability factor.
    source, reply_locals = _effective_reply_localparts(email)
    unmonitored_hits = [loc for loc in reply_locals if loc in _UNMONITORED_LOCALPARTS]
    if reply_locals and unmonitored_hits:
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.reply_to_monitored",
                severity=Severity.LOW,
                passed=False,
                message=(
                    f"Effective reply address (via {source}) is an unmonitored "
                    f"mailbox: {unmonitored_hits}. Microsoft sender guidance: "
                    "From / Reply-To should be valid, reflect the true sending "
                    "domain, and be able to receive replies. Replying drives "
                    "engagement signals that improve inbox placement."
                ),
                details={"source": source, "unmonitored": unmonitored_hits},
            )
        )
    elif reply_locals:
        findings.append(
            Finding(
                check=f"{CHECK_PREFIX}.reply_to_monitored",
                severity=Severity.INFO,
                passed=True,
                message=(f"Effective reply address (via {source}) is not a noreply mailbox."),
            )
        )

    return findings
