"""Deterministic DMARC record classifier (no LLM).

Encodes every pattern from the reference DMARC conversation
into a rules engine. Input: one DmarcRecord + the report's policy +
optional baseline of known sending IPs. Output: ClassificationResult
with classification tag, severity, plain-English explainer, and
optional suggested action.

The classifier intentionally short-circuits — every rule sits in an
explicit branch ordered most-specific → most-general. The first
matching rule wins. No statistical scoring, no LLM judgment, no
ambiguity about what fired.

Pattern bank (in match order):

  1. BOUNCE              empty envelope_from → normal NDR, ignore.
  2. POLICY_OVERRIDE_ARC receiver overrode failures via ARC chain.
  3. POLICY_OVERRIDE_FWD receiver overrode via forwarded_email flag.
  4. DKIM_TEMPERROR      transient receiver DNS hiccup, not a real fail.
  5. FORWARDING_ARTIFACT DKIM passes on header_from, SPF on a
                         different domain (subscriber forwarded).
  6. SPOOFING_BLOCKED    both fail, disposition=quarantine|reject.
  7. SPOOFING_DELIVERED  both fail, disposition=none — danger.
  8. GATEWAY_RELAY       source kind=gateway, DKIM broken on relay.
  9. NEW_LEGIT_ESP       new IP, fingerprint = recognised ESP.
 10. NEW_UNKNOWN_IP      new IP, no ESP match — escalate.
 11. ESP_SOFTFAIL_OK     known ESP, SPF softfail expected, DKIM OK.
 12. CLEAN               DKIM+SPF pass, disposition=none.
 13. UNCLASSIFIED        catch-all (very rare).

Each rule emits a frozen explainer template filled with the record's
own field values — matches the tone of the human-readable summaries
in the reference conversation.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from engine.severity import Severity

from .esp_fingerprint import ESPMatch, resolve_identity
from .esp_fingerprint import classify as _classify_ip
from .parser import DmarcPolicyPublished, DmarcRecord

# Identity kinds that are inherently a recognised sender, not a spoofer on
# random infrastructure (curated CIDR / vendor PTR match). A failing message
# from one of these is an auth gap to fix, never an impostor.
_CURATED_KINDS = frozenset({"esp", "gateway", "microsoft", "google"})

Classification = Literal[
    "bounce",
    "policy_override_arc",
    "policy_override_fwd",
    "policy_override_sampled",
    "policy_override_mailing_list",
    "dkim_temperror",
    "forwarding_artifact",
    "spoofing_blocked",
    "spoofing_delivered",
    "gateway_relay",
    "sender_auth_gap",
    "new_legit_esp",
    "new_unknown_ip",
    "esp_softfail_ok",
    "clean",
    "unclassified",
]


class ClassificationResult(BaseModel):
    classification: Classification
    severity: Severity
    headline: str  # one-line summary
    explainer: str  # plain-English paragraph
    suggested_action: str | None = None
    source_match: ESPMatch | None = None
    is_new_ip: bool = False  # only true when baseline was provided and ip absent
    details: dict = Field(default_factory=dict)


def _has_reason(record: DmarcRecord, type_name: str) -> bool:
    return any(r.type == type_name for r in record.reasons)


def _dkim_temperror(record: DmarcRecord) -> bool:
    return any(d.result == "temperror" for d in record.auth_dkim)


def _envelope_empty(record: DmarcRecord) -> bool:
    """True ONLY when the report explicitly carried an empty <envelope_from>
    element — the RFC 5321 marker for a bounce / NDR.

    Critically NOT triggered by envelope_from=None (field missing from the
    report entirely). Treating "missing" as "empty" silently mass-classified
    every record from reporters that omit the field as BOUNCE, which
    surfaced as 'everything is bounces' in the UI."""
    return record.envelope_from == ""


def _spf_envelope_aligned(record: DmarcRecord, header_from: str) -> bool:
    """True iff the SPF envelope domain matches the header_from (one of
    the auth_spf domains equals header_from)."""
    if not header_from:
        return False
    h = header_from.lower()
    return any((s.domain or "").lower() == h for s in record.auth_spf)


def _dkim_domain_aligned(record: DmarcRecord, header_from: str) -> bool:
    """True iff one of the auth_dkim signing domains aligns with
    header_from AND that result is 'pass'."""
    if not header_from:
        return False
    h = header_from.lower()
    return any((d.domain or "").lower() == h and d.result == "pass" for d in record.auth_dkim)


def _is_known_provider(ident, known_providers: set[str] | None) -> bool:
    """True when the source is a recognised sender — either a curated
    identity (CIDR/vendor match) or a real provider identity (a named
    domain/host) seen in past reports. A failing message from a known
    provider is an auth gap, not a spoof.

    Crucially, an IP-block fallback key (kind 'unknown'/'cloud') seen
    before does NOT count: otherwise a repeat spoofer downgrades itself
    from spoof to auth-gap just by having appeared once. Only resolved
    'domain'/'infra' identities carry history weight."""
    if ident.kind in _CURATED_KINDS:
        return True
    if ident.kind in ("domain", "infra"):
        return known_providers is not None and ident.provider_key in known_providers
    return False


# A known sender's auth gap escalates from "quiet note" to "fix this" once
# it has failed in this many PRIOR reporting periods — a pattern, not a
# one-off forward. (Move D: recurrence/trend.)
_RECUR_PERIODS = 2


def classify_record(
    record: DmarcRecord,
    policy: DmarcPolicyPublished | None = None,
    known_providers: set[str] | None = None,
    fail_history: dict[str, int] | None = None,
) -> ClassificationResult:
    """Run the rule cascade and return the first match.

    `known_providers` is the per-domain baseline of sender identities
    (esp_fingerprint provider_key) seen in past reports. When provided,
    the classifier keys new-sender / known-sender rules on provider, not
    raw IP; when None, new-sender detection is skipped.

    `fail_history` maps provider_key → number of PRIOR reporting periods
    that provider failed alignment. Used to escalate a recurring auth gap
    from noise to an actionable pattern; absent/None means treat every gap
    as a first occurrence.
    """
    src = _classify_ip(record.source_ip)
    # Composite identity drives the spoof-vs-known decision (src, the raw
    # PTR match, is kept only for the source_match metadata field).
    ident = resolve_identity(record)
    known = _is_known_provider(ident, known_providers)
    header_from = (record.header_from or "").lower()
    domain = (policy.domain if policy else header_from).lower()
    policy_p = policy.p if policy else None
    dkim_pass = record.policy_dkim == "pass"
    spf_pass = record.policy_spf == "pass"
    fail_both = not dkim_pass and not spf_pass
    dispo = record.disposition

    base = {
        "source_ip": record.source_ip,
        "source_vendor": src.name,
        "source_kind": src.kind,
        "header_from": header_from,
        "envelope_from": record.envelope_from,
        "envelope_to": record.envelope_to,
        "policy_p": policy_p,
        "count": record.count,
    }

    # ─── 1. Bounce — empty envelope = NDR ────────────────────────
    if _envelope_empty(record):
        return ClassificationResult(
            classification="bounce",
            severity=Severity.INFO,
            headline="Bounce / NDR — normal mail behaviour",
            explainer=(
                f"This record is a bounce message ({record.count} email). "
                f"Bounces always have an empty envelope sender to "
                f"prevent infinite loops. SPF / DKIM failures here are "
                f"expected — nothing you can do about it, nothing to "
                f"action."
            ),
            source_match=src,
            details=base,
        )

    # ─── 2. ARC override ─────────────────────────────────────────
    if _has_reason(record, "local_policy") and any(
        "arc" in (r.comment or "").lower() for r in record.reasons
    ):
        return ClassificationResult(
            classification="policy_override_arc",
            severity=Severity.INFO,
            headline="Receiver trusted via ARC chain",
            explainer=(
                "The receiver applied an ARC override — they trusted "
                "the original authentication that came in before "
                "forwarding. DKIM may show as failing in this row but "
                "the email still passed end-to-end. No action."
            ),
            source_match=src,
            details=base,
        )

    # ─── 3. Forwarded-email override ─────────────────────────────
    if _has_reason(record, "forwarded"):
        return ClassificationResult(
            classification="policy_override_fwd",
            severity=Severity.INFO,
            headline="Forwarded email override applied by receiver",
            explainer=(
                "The receiver flagged this as a forwarded message. "
                "Auth failures here come from the forwarding hop, not "
                "the original send. No action."
            ),
            source_match=src,
            details=base,
        )

    # ─── 3a. Sampled-out — pct<100 didn't select this message ────
    # Critical false-alarm suppressor. With p=reject + pct<100, a row
    # carrying disposition='none' looks like the policy was ignored
    # ('why didn't they reject?!'). The reporter marks it sampled_out
    # because the published pct simply didn't pick this email for
    # enforcement. Expected behaviour, not a problem.
    if _has_reason(record, "sampled_out"):
        published_pct = policy.pct if (policy and policy.pct is not None) else None
        return ClassificationResult(
            classification="policy_override_sampled",
            severity=Severity.INFO,
            headline="Sampled-out — pct rollout didn't pick this message",
            explainer=(
                f"Your published policy is "
                f"p={policy_p or '?'} pct={published_pct or '?'}, and this "
                f"row was randomly NOT selected for enforcement. The "
                f"receiver delivered it under the prior policy. This is "
                f"the expected behaviour of a pct rollout — not a failure."
            ),
            source_match=src,
            details=base,
        )

    # ─── 3b. Mailing-list override ───────────────────────────────
    # Mailman / Google Groups / Discourse style. The list re-sends mail
    # with its own envelope and Subject prefix; original DKIM stays
    # intact but SPF breaks because the envelope now comes from the list
    # domain. Receivers honor list mail with this override.
    if _has_reason(record, "mailing_list"):
        return ClassificationResult(
            classification="policy_override_mailing_list",
            severity=Severity.INFO,
            headline="Mailing-list override applied by receiver",
            explainer=(
                "A mailing list re-distributed this message. The list's "
                "server signs with its own envelope so SPF on your domain "
                "naturally fails on this hop. The receiver recognised the "
                "list pattern and delivered it anyway. No action."
            ),
            source_match=src,
            details=base,
        )

    # ─── 4. DKIM temperror ───────────────────────────────────────
    if _dkim_temperror(record) and dispo == "none":
        return ClassificationResult(
            classification="dkim_temperror",
            severity=Severity.INFO,
            headline="Transient DNS hiccup on the receiver",
            explainer=(
                f"The receiver couldn't reach your DKIM TXT record at "
                f"lookup time ({record.count} email). Temporary DNS "
                f"timeout on their side, not a real DKIM failure. "
                f"Delivered fine. No action."
            ),
            source_match=src,
            details=base,
        )

    # ─── 5. Known-ESP softfail-only ──────────────────────────────
    # Must precede forwarding_artifact: Brevo / Kit-CNAME look like
    # forwarding (SPF envelope on a different domain) but the source
    # is the ESP itself, not a subscriber-side forwarder. Only fires
    # for kind=='esp' — M365 and Google legitimate sends through a
    # different-tenant forwarder fall through to forwarding_artifact.
    if (
        _dkim_domain_aligned(record, header_from)
        and dispo == "none"
        and src.kind == "esp"
        and not _spf_envelope_aligned(record, header_from)
    ):
        return ClassificationResult(
            classification="esp_softfail_ok",
            severity=Severity.INFO,
            headline=f"{src.name} — expected SPF softfail, DKIM covers it",
            explainer=(
                f"{src.name} uses a CNAME-based SPF setup, so the "
                f"envelope domain doesn't align with {header_from}. "
                f"DKIM passes cleanly, DMARC passes overall, every "
                f"email delivered. This is permanent and expected — "
                f"adding their SPF include doesn't change what the "
                f"reports show."
            ),
            source_match=src,
            details=base,
        )

    # ─── 6. Forwarding artifact (subscriber-side) ────────────────
    # DKIM passes on header_from, SPF envelope is a different domain,
    # delivered, AND the source is NOT a recognised ESP (those are
    # caught by rule 5).
    if (
        _dkim_domain_aligned(record, header_from)
        and not _spf_envelope_aligned(record, header_from)
        and dispo == "none"
    ):
        fwd_dom = next((s.domain for s in record.auth_spf if s.domain), "?")
        return ClassificationResult(
            classification="forwarding_artifact",
            severity=Severity.INFO,
            headline=f"Subscriber-side forwarding via {fwd_dom}",
            explainer=(
                f"A recipient at {fwd_dom!r} has email forwarding "
                f"configured — the SPF envelope shows their domain, "
                f"not yours. DKIM still passes under {header_from}, "
                f"so DMARC passes overall. Not a problem you can fix "
                f"on your side."
            ),
            source_match=src,
            details=base,
        )

    # ─── 7. Gateway relay broke DKIM ─────────────────────────────
    # Must precede the spoofing rules: a gateway relay (Avanan,
    # Mimecast, IronPort, Forcepoint) breaking DKIM looks like
    # spoofing on the surface (DKIM+SPF fail) but is actually the
    # recipient's own security stack misbehaving.
    if ident.kind == "gateway" and not dkim_pass and dispo in ("none", "quarantine", "reject"):
        return ClassificationResult(
            classification="gateway_relay",
            severity=Severity.LOW,
            headline=f"{src.name} relay broke DKIM — recipient-side issue",
            explainer=(
                f"{src.name} is a security gateway in front of the "
                f"recipient. They re-relayed the email; the "
                f"modification during relay broke your DKIM "
                f"signature. Not your misconfiguration. The "
                f"recipient's IT can fix it by configuring the "
                f"gateway to preserve original DKIM, but that's "
                f"their lift."
            ),
            source_match=src,
            details=base,
        )

    # ─── 7b. Known-provider auth gap (2×2 top-right) ─────────────
    # A sender we recognise (curated identity, or a provider seen in past
    # reports) failed alignment. NOT a spoof — and never hidden. Surfaced
    # as a fixable auth gap, framed by cumulative risk, not this one email.
    if fail_both and known:
        prior_periods = (fail_history or {}).get(ident.provider_key, 0)
        recurring = prior_periods >= _RECUR_PERIODS
        # Enforcing policy (blocking real mail) is worse than monitoring; a
        # recurring pattern is worse than a one-off. Escalate on both axes.
        if policy_p in (None, "none"):
            gap_sev = Severity.MEDIUM if recurring else Severity.LOW
        else:
            gap_sev = Severity.HIGH if recurring else Severity.MEDIUM

        if recurring:
            headline = f"{ident.name} — recurring authentication gap"
            explainer = (
                f"{ident.name} has now failed to authenticate as {header_from} "
                f"across {prior_periods + 1} reporting periods — DKIM and SPF "
                f"both fail to align. This is a pattern, not a stray forward, "
                f"and a persistent unauthenticated stream drags your inbox "
                f"placement. Fix the sender's setup."
            )
            gap_action = (
                f"Set up {ident.name} to sign with DKIM and pass SPF for "
                f"{domain}. It has failed repeatedly, so this is costing you "
                f"deliverability until it's fixed."
            )
        else:
            headline = f"{ident.name} — authentication gap, not a spoof"
            explainer = (
                f"{record.count} email from {ident.name} sent as "
                f"{header_from} but didn't authenticate as you — DKIM and SPF "
                f"both failed to align. This is a sender you use, not an "
                f"impostor. A single miss is almost always a forward or list "
                f"and won't hurt you; a rising share from the same source can "
                f"drag your inbox placement over time."
            )
            if policy_p in (None, "none"):
                gap_action = (
                    f"A one-off miss from a sender you use is usually a forward "
                    f"or mailing list — safe to ignore. If mail from "
                    f"{ident.name} keeps failing, check its SPF and DKIM so it "
                    f"authenticates as {domain}."
                )
            else:
                gap_action = (
                    f"Your p={policy_p} policy means these are being filtered "
                    f"or blocked. Set up {ident.name} to sign with DKIM and "
                    f"pass SPF for {domain}, or this mail keeps getting lost."
                )
        return ClassificationResult(
            classification="sender_auth_gap",
            severity=gap_sev,
            headline=headline,
            explainer=explainer,
            suggested_action=gap_action,
            source_match=src,
            details=base,
        )

    # ─── 8. Spoofing blocked ─────────────────────────────────────
    if fail_both and not known and dispo in ("quarantine", "reject"):
        return ClassificationResult(
            classification="spoofing_blocked",
            severity=Severity.INFO,
            headline=f"Spoof attempt {dispo}d — policy working",
            explainer=(
                f"{record.count} email from {record.source_ip} "
                f"({src.name or 'unknown'}) tried to send as "
                f"{header_from} with no valid DKIM or SPF. Your "
                f"p={policy_p or 'none'} policy {dispo}d it. Working "
                f"as intended."
            ),
            source_match=src,
            details=base,
        )

    # ─── 7. Spoofing delivered ───────────────────────────────────
    if fail_both and not known and dispo == "none":
        if policy_p in (None, "none"):
            action = (
                f"Move {domain} from p=none to p=quarantine to start "
                f"blocking these. Add `pct=50` first for a soft rollout."
            )
        else:
            action = (
                f"Receiver did not honour your published p={policy_p}. "
                f"Sometimes happens with whitelisted senders or ARC "
                f"chains — investigate the recipient's mail filter."
            )
        return ClassificationResult(
            classification="spoofing_delivered",
            severity=Severity.HIGH,
            headline="Spoof attempt delivered — investigate",
            explainer=(
                f"{record.count} email from {record.source_ip} "
                f"({src.name or 'unknown'}) sent as {header_from} with "
                f"failing DKIM and SPF, and the receiver delivered it. "
                f"Published policy is p={policy_p or 'none'}."
            ),
            suggested_action=action,
            source_match=src,
            details=base,
        )

    # ─── 9 / 10. New-IP rules (only when baseline provided) ──────
    # Only fire when the record itself has SOMETHING to flag —
    # auth failure or non-none disposition. A new IP that's also
    # fully clean (DKIM pass + SPF pass + disposition=none) just
    # means a recognised sender showed up for the first time, which
    # is exactly the desired state. Falling through to the clean
    # rule below avoids alert-fatigue on legitimate first sends.
    fully_clean = dkim_pass and spf_pass and dispo == "none"
    if (
        known_providers is not None
        and ident.provider_key not in known_providers
        and not fully_clean
    ):
        is_new = True
        if ident.kind in ("esp", "microsoft", "google"):
            return ClassificationResult(
                classification="new_legit_esp",
                severity=Severity.MEDIUM,
                headline=f"New sender: {src.name}",
                explainer=(
                    f"First time {src.name} ({record.source_ip}) "
                    f"appears in your DMARC history for {domain}. "
                    f"Looks legitimate based on reverse-DNS. If you "
                    f"recently added {src.name} as a sender, make "
                    f"sure SPF includes their range so future reports "
                    f"come back clean."
                ),
                suggested_action=(
                    f"If you started using {src.name}, add their SPF "
                    f"include to your {domain} record."
                ),
                source_match=src,
                is_new_ip=is_new,
                details=base,
            )
        # Cloud / unknown IP — escalate.
        if dispo == "none" and (dkim_pass or spf_pass):
            # Authenticated but new — milder.
            severity = Severity.MEDIUM
        else:
            severity = Severity.HIGH
        return ClassificationResult(
            classification="new_unknown_ip",
            severity=severity,
            headline=f"New unknown sender: {record.source_ip}",
            explainer=(
                f"{record.source_ip} ({src.name}) has never been seen "
                f"in your DMARC history for {domain}. Reverse-DNS "
                f"doesn't match any recognised ESP or gateway. If you "
                f"don't recognise this server, treat as a spoofing "
                f"probe — your policy will catch it on the next send."
            ),
            suggested_action=(
                f"Check if anyone on your team has spun up a new tool "
                f"on {src.name or 'this host'} that sends as {domain}. "
                f"If not, the policy is doing its job; monitor for "
                f"repeats."
            ),
            source_match=src,
            is_new_ip=is_new,
            details=base,
        )

    # ─── 11. Clean ────────────────────────────────────────────────
    # DMARC passes when EITHER mechanism aligns — so DKIM-pass/SPF-fail or
    # SPF-pass/DKIM-fail, delivered, is a clean send, not an anomaly. (A
    # single-mechanism pass is fine; the missing one only matters for
    # resilience, surfaced by the domain-health checks, not here.)
    if (dkim_pass or spf_pass) and dispo == "none":
        return ClassificationResult(
            classification="clean",
            severity=Severity.INFO,
            headline="Clean send",
            explainer=(
                f"{record.count} email from {ident.name} — authenticated and "
                f"delivered, DMARC passed. Nothing to flag."
            ),
            source_match=src,
            details=base,
        )

    # ─── 13. Catch-all ───────────────────────────────────────────
    return ClassificationResult(
        classification="unclassified",
        severity=Severity.LOW,
        headline="Unclassified record",
        explainer=(
            f"{record.count} email from {record.source_ip} "
            f"({src.name}) — DKIM={record.policy_dkim}, "
            f"SPF={record.policy_spf}, disposition={dispo}. "
            f"Didn't match a known pattern. Worth a manual look."
        ),
        source_match=src,
        details=base,
    )
