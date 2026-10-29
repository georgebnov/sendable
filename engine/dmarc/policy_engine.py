"""policy_engine.py

Fully deterministic (NO LLM) decision engine for two coupled problems:

  1. DMARC enforcement ladder   p=none -> quarantine -> reject, ramping pct
  2. SPF / alignment remediation (the harder part)

THE UNIFYING RULE
-----------------
You may climb the DMARC ladder ONLY when no *legitimate* sender is failing
DMARC alignment. Advancing while a real sender is unaligned would start
blocking that sender's own mail. So the SPF/alignment tree is a GATE on the
ladder, not a parallel feature:

    blockers = legitimate senders that are NOT dmarc-aligned
    if blockers: fix them first (cannot advance)
    elif clean for N weeks AND enough data: advance one rung
    else: hold

Everything here is a pure function of inputs you already compute (the
classifier + a DNS read of the published SPF/DMARC records). Same inputs ->
same output, every time. Feed the returned Action straight into the UI:
status pill + title + detail + suggested_action (+ new_record when relevant).
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum

from engine.dmarc.spf_merge import merge_spf

# ----------------------------------------------------------------------------
# Tunable thresholds (config, not logic)
# ----------------------------------------------------------------------------
SPF_LOOKUP_LIMIT = 10  # RFC 7208: >10 DNS lookups => PermError
# A single low-volume unaligned source is a SOURCE problem (authenticate that
# sender), never a reason to roll the whole domain's policy back. Only a bleed
# that is this share of total volume — or comes from more than one source —
# is "domain-wide" enough to put the policy lever on the table.
DOMAIN_WIDE_BLEED_SHARE = 0.2

# The ladder. Each rung is (policy, pct). pct is ignored at 'none'.
LADDER: list[tuple[str, int]] = [
    ("none", 0),
    ("quarantine", 25),
    ("quarantine", 50),
    ("quarantine", 100),
    ("reject", 25),
    ("reject", 50),
    ("reject", 100),
]


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Tier(StrEnum):
    """Maps to the UI status pill."""

    GOOD = "good"  # green
    REVIEW = "review"  # amber
    ACTION = "action"  # red


# ----------------------------------------------------------------------------
# Inputs (all computed upstream by the classifier + a DNS read)
# ----------------------------------------------------------------------------
@dataclass
class Sender:
    name: str  # "Microsoft 365", "SendGrid", "Relay via megamailservers.com"
    volume: int
    dkim_aligned: bool
    spf_aligned: bool  # passed AND aligned with header-From org domain
    spf_authpassed: bool  # raw SPF pass (maybe on the ESP's own domain)
    has_dkim_signature: bool  # any DKIM sig present at all (even unaligned)
    legitimacy: str  # "legit" | "suspicious" | "unconfirmed"
    disposition: str  # none | quarantine | reject (what receiver did)
    esp_include: str | None = None  # e.g. "include:sendgrid.net" if known ESP
    classification: str | None = None  # classifier's tag — used for grouping +
    # row copy. e.g. "forwarding_artifact", "clean", "esp_softfail_ok",
    # "spoofing_blocked". The grouping layer routes off this when present,
    # and falls back to alignment heuristics when not.

    @property
    def dmarc_aligned(self) -> bool:
        return self.spf_aligned or self.dkim_aligned


@dataclass
class DmarcRecord:
    exists: bool
    p: str = ""  # none | quarantine | reject
    sp: str | None = None
    pct: int = 100
    adkim: str = "r"
    aspf: str = "r"


@dataclass
class SpfRecord:
    exists: bool
    record_count: int = 0  # number of v=spf1 TXT records found (must be 1)
    lookups: int = 0  # resolved DNS-lookup mechanism count
    all_qualifier: str = ""  # "-" | "~" | "?" | "+" | "" (missing 'all')
    raw: str = ""


@dataclass
class ReportSummary:
    """What the reports a user passed actually contain.

    This describes one batch of files and never a history. There is no span
    here on purpose: a user can download one report today and the next six
    months from now, so counting the dates inside a batch and calling the
    result a period would claim something nobody watched.

    `total_volume` is the plain sum of the message counts in the files, which
    is a fact about the files rather than a claim about time.
    """

    senders: list[Sender]
    total_volume: int


# ----------------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------------
@dataclass
class Action:
    code: str
    tier: Tier
    severity: Severity
    title: str
    detail: str
    suggested_action: str
    new_record: str | None = None  # exact TXT to publish, when action is "publish X"


@dataclass
class EngineResult:
    primary: Action  # the one thing to surface at the top
    spf_findings: list[Action] = field(default_factory=list)
    ladder_decision: Action | None = None
    blockers: list[Sender] = field(default_factory=list)


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def _ladder_index(rec: DmarcRecord) -> int:
    if not rec.exists:
        return -1
    for i, (p, pct) in enumerate(LADDER):
        if p == rec.p and (p == "none" or pct == rec.pct):
            return i
    # Off a rung. A record can hold any percentage, so count the domain as the
    # highest rung of its own policy it has already passed. Then the next step
    # is always stronger than what it publishes now.
    #
    # This used to take the first rung of the policy instead. A domain at
    # p=reject; pct=90 counted as reject at 25, so the step after it was reject
    # at 50, and the advice read "the next step is reject at 50%" while handing
    # over a record that weakens the domain from 90 to 50. A downgrade dressed
    # as progress, on the one axis where going backwards re-opens the domain to
    # spoofing.
    passed = [i for i, (p, pct) in enumerate(LADDER) if p == rec.p and pct <= rec.pct]
    if passed:
        return passed[-1]

    # Below the lowest rung of its own policy, so it has not reached that rung
    # and the rung below is where it stands. A domain at quarantine 10 counts
    # as none, and the step it is offered is quarantine 25 rather than 50.
    first = [i for i, (p, _) in enumerate(LADDER) if p == rec.p]
    return max(first[0] - 1, 0) if first else 0


def _build_record(policy: str, pct: int, rua: str, current: DmarcRecord | None = None) -> str:
    """The exact TXT record to publish.

    This is the most consequential string the engine emits: SKILL.md tells the
    agent to have the user paste it into DNS. Two things it must get right.

    It carries forward every tag it is not deliberately changing. `current` is the
    record the domain publishes now. Emitting only p, rua and pct meant a user at
    `p=none; sp=reject; adkim=s; aspf=s` who followed ADVANCE pasted
    `p=quarantine; rua=...; pct=25` and silently lost subdomain enforcement and
    strict alignment, which is the opposite of advancing.

    `rua` may arrive with or without its scheme. Prepending a second one produced
    `rua=mailto:mailto:dmarc@example.com`, which is not a valid DMARC URI, so
    receivers drop the tag and stop sending the reports this tool reads.
    """
    address = rua.strip()
    if not address.lower().startswith("mailto:"):
        address = f"mailto:{address}"
    parts = ["v=DMARC1", f"p={policy}", f"rua={address}"]

    if policy != "none" and pct < 100:
        parts.append(f"pct={pct}")

    # Tags the caller is not changing. Kept in the order a reader expects, and
    # only when the domain actually publishes them.
    if current is not None:
        if current.sp:
            parts.append(f"sp={current.sp}")
        # "r" is the default for both, so emitting it adds noise. "s" is a
        # deliberate choice the user made and must survive.
        if current.adkim and current.adkim != "r":
            parts.append(f"adkim={current.adkim}")
        if current.aspf and current.aspf != "r":
            parts.append(f"aspf={current.aspf}")

    return "; ".join(parts)


# Classifier tags for hops the sender does NOT control — a recipient's
# forwarder or inbound security gateway. When one of these is the source of
# blocked mail, there is no sender-side fix; the only honest output is
# "expected, nothing to do" — never a policy rollback.
_UNCONTROLLABLE_TAGS = {
    "forwarding_artifact",
    "gateway_relay",
    "policy_override_fwd",
    "policy_override_mailing_list",
    # A delivery-status notification, not a send. summary._LEGIT already says
    # treating it as legit "keeps it out of the blocker list", which was not true
    # until _is_blocker consulted this set.
    "bounce",
}


def _fixable_blockers(blockers: list[Sender]) -> list[Sender]:
    """The blockers the sender can actually do something about.

    Drops hops on the recipient's side. Those still belong in `blockers` itself,
    because the bleeding branch uses that list to reassure the user when such a
    hop is being rejected, which is a real thing to say and not a thing to fix.
    """
    return [s for s in blockers if s.classification not in _UNCONTROLLABLE_TAGS]


def _is_blocker(s: Sender) -> bool:
    """A sender that is not aligned and cannot simply be ignored.

    A confirmed spoof is ignored, because advancing is what stops it.
    "unconfirmed" is not: a recognised sender failing alignment is the sender's
    own mail, and tightening would start rejecting it.

    This list feeds two different questions, and they want different answers for a
    recipient-side relay. "Is this sender's mail being rejected right now" wants
    the relay included, so the bleeding branch can say the block was expected.
    "Does this stop me advancing" does not, which `_fixable_blockers` answers.
    """
    return (not s.dmarc_aligned) and s.legitimacy != "suspicious"


# ----------------------------------------------------------------------------
# SPF / alignment decision tree  (the harder part: every case enumerated)
# ----------------------------------------------------------------------------
def spf_findings(spf: SpfRecord, senders: list[Sender]) -> list[Action]:
    out: list[Action] = []
    # SPF_SENDER_NOT_AUTHORIZED findings for known-ESP senders, gathered so one
    # merged "paste this" record (published SPF + every missing include) can be
    # stamped onto each after the per-sender loop.
    _unauth_actions: list[Action] = []
    _unauth_includes: list[str] = []

    # --- A. record-level health (affects ALL senders) ---
    if not spf.exists:
        out.append(
            Action(
                "SPF_MISSING",
                Tier.ACTION,
                Severity.HIGH,
                "No SPF record",
                "Receivers have no list of servers allowed to send as you. SPF "
                "authentication fails for every source.",
                "Publish one SPF record listing your senders, e.g. v=spf1 include:<your-esp> -all",
            )
        )
    elif spf.record_count > 1:
        out.append(
            Action(
                "SPF_MULTIPLE",
                Tier.ACTION,
                Severity.HIGH,
                "More than one SPF record",
                "Two or more v=spf1 records is a PermError. Receivers treat SPF as "
                "broken, so it fails for everyone.",
                "Merge them into a single record with all includes combined.",
            )
        )
    else:
        if spf.lookups > SPF_LOOKUP_LIMIT:
            out.append(
                Action(
                    "SPF_TOO_MANY_LOOKUPS",
                    Tier.ACTION,
                    Severity.HIGH,
                    f"SPF exceeds {SPF_LOOKUP_LIMIT} DNS lookups ({spf.lookups})",
                    "Past the limit SPF returns PermError and fails for every "
                    "sender, even authorized ones.",
                    f"Reduce or flatten includes to get back under {SPF_LOOKUP_LIMIT} lookups.",
                )
            )
        q = spf.all_qualifier
        if q == "+":
            out.append(
                Action(
                    "SPF_PLUS_ALL",
                    Tier.ACTION,
                    Severity.HIGH,
                    "SPF ends in +all",
                    "+all authorizes the entire internet to send as you. It makes "
                    "SPF meaningless and invites spoofing.",
                    "Change +all to -all (hardfail) or ~all (softfail).",
                )
            )
        elif q in ("?", ""):
            out.append(
                Action(
                    "SPF_WEAK_ALL",
                    Tier.REVIEW,
                    Severity.MEDIUM,
                    "SPF has no enforcing 'all'" if q == "" else "SPF ends in ?all",
                    "A neutral/absent 'all' tells receivers to make no judgement on "
                    "unlisted servers, weakening protection.",
                    "End the record with -all once all your senders are listed.",
                )
            )
        elif q == "~":
            out.append(
                Action(
                    "SPF_SOFTFAIL",
                    Tier.GOOD,
                    Severity.LOW,
                    "SPF ends in ~all (softfail)",
                    "Fine while you roll out. ~all is permissive by design.",
                    "Tighten to -all once you're confident every sender is listed.",
                )
            )
        elif q == "-":
            out.append(
                Action(
                    "SPF_HARDFAIL",
                    Tier.GOOD,
                    Severity.INFO,
                    "SPF ends in -all",
                    "Strongest setting. Unlisted servers are rejected.",
                    "No action.",
                )
            )

    # --- B. per-sender alignment ---
    for s in senders:
        if s.legitimacy == "suspicious":
            continue  # spoof: SPF 'failing' for it is desired, not a finding

        if s.dmarc_aligned and s.spf_aligned:
            continue  # fully fine

        # legit sender that passes SPF but on the ESP's own domain (not aligned)
        if s.spf_authpassed and not s.spf_aligned:
            if s.dkim_aligned:
                out.append(
                    Action(
                        "SPF_SENDER_UNALIGNED_OK",
                        Tier.GOOD,
                        Severity.LOW,
                        f"{s.name}: SPF not aligned (DKIM carries it)",
                        "SPF passes on the ESP's bounce domain, so it doesn't align "
                        "but DKIM aligns, so DMARC passes. Optional hardening.",
                        "Optional: add a custom Return-Path (CNAME to the ESP) so "
                        "SPF aligns too, for belt-and-suspenders.",
                    )
                )
            else:
                out.append(
                    Action(
                        "SPF_SENDER_UNALIGNED_NODKIM",
                        Tier.ACTION,
                        Severity.HIGH,
                        f"{s.name}: nothing aligns",
                        "SPF passes but on the ESP's domain (no alignment), and DKIM "
                        "does not align either, so this sender FAILS DMARC.",
                        "Set up aligned DKIM with this provider (preferred), or a "
                        "custom Return-Path subdomain so SPF aligns.",
                    )
                )
            continue

        # legit sender that doesn't even pass SPF
        if not s.spf_authpassed:
            # forwarding: SPF can't survive a hop — unfixable, DKIM must carry it
            if s.dkim_aligned:
                out.append(
                    Action(
                        "SPF_FORWARD_EXPECTED",
                        Tier.GOOD,
                        Severity.INFO,
                        f"{s.name}: SPF fails (forwarded)",
                        "Forwarding breaks SPF by design. DKIM survived the hop, so "
                        "DMARC still passes.",
                        "No action. Forwarding cannot be fixed at the source.",
                    )
                )
            else:
                inc = f" ({s.esp_include})" if s.esp_include else ""
                act = Action(
                    "SPF_SENDER_NOT_AUTHORIZED",
                    Tier.ACTION,
                    Severity.HIGH,
                    f"{s.name}: not in your SPF",
                    "A legitimate-looking sender isn't authorized by SPF and has "
                    "no aligned DKIM, so it fails DMARC and will be blocked at "
                    "enforcement.",
                    f"Add this provider's include to your SPF record{inc}, then set up its DKIM.",
                )
                out.append(act)
                if s.esp_include:
                    _unauth_actions.append(act)
                    _unauth_includes.append(s.esp_include)

    # Attach the exact record to paste: published SPF + the missing known-ESP
    # includes, merged once and stamped onto each affected finding. Unknown-ESP
    # senders (no include to add) stay text-only — we don't hand out a record
    # that wouldn't actually authorize them.
    if _unauth_includes:
        merged, warning = merge_spf(
            spf.raw,
            _unauth_includes,
            all_qualifier=spf.all_qualifier or "~",
            current_lookups=spf.lookups,
            lookup_limit=SPF_LOOKUP_LIMIT,
        )
        for act in _unauth_actions:
            act.new_record = merged
            if warning:
                act.suggested_action += f" Heads up: {warning}"
    return out


def apply_live_spf_fixes(spf: SpfRecord, senders: list[Sender]) -> list[Sender]:
    """Clear "not in your SPF" alarms the sender has already fixed.

    A DMARC aggregate report describes mail that was sent days ago. When someone
    adds a provider's SPF include today, the reports keep showing that provider
    failing SPF until the old reports age out of the summary, which takes weeks.
    This reads the live published SPF record instead: when the provider's include
    is in the record now, mark that sender as passing and aligned, so the alarm
    drops.

    The match is a substring test on the domain part of the include token. That
    is enough to tell whether the record names that provider. A full per-source
    SPF evaluation against the published record is a later refinement.

    The assumption is that a published include means that sender will pass and
    align from now on. That holds for a provider which sends as the user's own
    domain, such as Google Workspace or Microsoft 365. A third-party provider
    that sends from its own bounce domain can pass SPF without aligning, so this
    function can hide that case.

    Returns a new list. The senders passed in are not changed.
    """
    if not spf.exists or not spf.raw:
        return senders
    out: list[Sender] = []
    for sender in senders:
        # esp_include looks like "include:_spf.google.com". Compare the domain
        # part, so the test works whether or not the prefix was stored.
        token = (sender.esp_include or "").split(":", 1)[-1]
        if token and not sender.spf_authpassed and token in spf.raw:
            out.append(replace(sender, spf_authpassed=True, spf_aligned=True))
        else:
            out.append(sender)
    return out


# ----------------------------------------------------------------------------
# DMARC ladder decision  (gated by the blockers above)
# ----------------------------------------------------------------------------
def dmarc_decision(rec: DmarcRecord, summary: ReportSummary, rua: str) -> Action:
    senders = summary.senders
    blockers = [s for s in senders if _is_blocker(s)]

    # 0. No record at all -> start at none/monitor.
    if not rec.exists:
        return Action(
            "PUBLISH_INITIAL",
            Tier.ACTION,
            Severity.HIGH,
            "No DMARC record yet",
            "You have no policy, so you get no visibility and no protection.",
            "Publish a monitoring record to start collecting reports.",
            new_record=_build_record("none", 0, rua, current=rec),
        )

    idx = _ladder_index(rec)

    # 1. Legit mail is being actively quarantined/rejected RIGHT NOW.
    #    Branch source-vs-domain BEFORE touching the ladder: a single
    #    low-volume source failing is a SOURCE problem — fix that sender's
    #    auth, never roll the whole domain back (doing so re-exposes the
    #    domain to every spoofer to rescue a handful of messages). Only a
    #    domain-wide or high-volume-critical bleed earns the policy lever,
    #    and even then only when there's an actual relaxation to step to.
    bleeding = [s for s in blockers if s.disposition in ("quarantine", "reject")]
    if bleeding:
        # Only sources you can actually authenticate drive the "fix / ease"
        # advice. A recipient-side gateway or forwarder can be bleeding too,
        # but it has no sender-side fix and must never appear in an
        # "authenticate X" instruction (you cannot authenticate Avanan). Fall
        # back to the full list only when EVERY bleeding source is
        # uncontrollable — that's the reassurance case below.
        controllable = [s for s in bleeding if s.classification not in _UNCONTROLLABLE_TAGS]
        primary = controllable or bleeding
        names = ", ".join(s.name for s in primary)
        bleeding_volume = sum(s.volume for s in primary)
        share = bleeding_volume / max(summary.total_volume, 1)
        # `bool(controllable)` first. When every bleeding source is a hop on the
        # recipient's side, `primary` falls back to that list and `share` is
        # computed from it, so a single gateway carrying 20% of volume reached
        # the domain-wide branch and returned ROLLBACK with a record weakening
        # anti-spoofing, to fix something the sender cannot reach. The tag set's
        # own comment says these must never produce a rollback.
        domain_wide = bool(controllable) and (
            len(controllable) > 1 or share >= DOMAIN_WIDE_BLEED_SHARE
        )
        spoof_blocked = sum(s.volume for s in senders if s.legitimacy == "suspicious")
        spoof_note = (
            f" Meanwhile your policy is correctly blocking {spoof_blocked} "
            "impersonation attempt(s), so do not weaken it."
            if spoof_blocked
            else ""
        )

        if not domain_wide:
            # Single low-volume source — policy stays put (new_record=None).
            if not controllable:
                # (c) recipient-side forward/gateway — no sender-side fix exists.
                return Action(
                    "FORWARD_BLEED_OK",
                    Tier.REVIEW,
                    Severity.LOW,
                    "A forwarded copy was blocked. This is expected.",
                    f"{names} re-sent your mail from infrastructure you don't "
                    f"control, so it failed authentication and was held "
                    f"({bleeding_volume} low-volume message(s))." + spoof_note,
                    "Nothing to fix on your side. This is a recipient's "
                    "forwarder or security gateway. Easing your DMARC policy to "
                    "rescue a few uncontrollable forwards isn't worth it.",
                )
            # (b) your own sender, fixable — fix the source, not the policy.
            fixable = next((s for s in bleeding if s.esp_include), None)
            how = (
                f"add {fixable.esp_include} to your SPF record and turn on aligned DKIM"
                if fixable
                else f"authenticate {names} (SPF include + aligned DKIM)"
            )
            return Action(
                "FIX_SENDER",
                Tier.ACTION,
                Severity.HIGH,
                "Your mail is being blocked. Fix the sender.",
                f"{names} is legitimate but isn't authenticated for your domain, "
                f"so the receiver is quarantining/rejecting it ({bleeding_volume} "
                f"message(s) lost). The fix is on that sender, not your policy." + spoof_note,
                f"To stop the loss, {how}. Leave your DMARC policy as it is.",
            )

        # Domain-wide / high-volume-critical bleed: the policy lever is on the
        # table. Guard against a no-op — only roll back when there is an actual
        # relaxation below the current rung.
        target_idx = max(idx - 1, 0)
        if target_idx >= idx:
            # Already at the lowest rung — nothing to relax. The only fix is
            # to authenticate the sender(s).
            return Action(
                "FIX_SENDER",
                Tier.ACTION,
                Severity.HIGH,
                "Your own mail is being blocked",
                f"{names} is legitimate but unaligned and your policy is blocking "
                "it. You're already at the lowest enforcement, so the only fix is "
                "to authenticate the sender." + spoof_note,
                f"Authenticate {names} (SPF include + aligned DKIM).",
            )
        step_p, step_pct = LADDER[target_idx]
        step_label = step_p + (f" at {step_pct}%" if step_p != "none" and step_pct < 100 else "")
        cur_label = f"p={rec.p}" + (f", pct={rec.pct}" if rec.pct < 100 else "")
        return Action(
            "ROLLBACK",
            Tier.ACTION,
            Severity.HIGH,
            "Your own mail is being blocked",
            f"{names} is legitimate but unaligned, and your current policy "
            f"({cur_label}) is quarantining/rejecting real mail across your "
            "domain.",
            f"Temporarily ease to {step_label} while you authenticate {names}, then climb back up.",
            new_record=_build_record(step_p, step_pct, rua, current=rec),
        )

    # 2. BLOCKED: a legit/unconfirmed sender is unaligned (would break if advanced).
    #
    # Only senders the user can actually fix. A recipient's security gateway,
    # mailing list, forwarder, or a bounce notification cannot be authenticated by
    # the sender, so counting them here produced "Authenticate Mimecast relay
    # (SPF include + aligned DKIM)", an instruction this file's own comments call
    # impossible, and held every such domain off the ladder permanently.
    fixable_blockers = _fixable_blockers(blockers)
    if fixable_blockers:
        names = ", ".join(s.name for s in fixable_blockers)
        return Action(
            "BLOCKED_FIX_SENDERS",
            Tier.REVIEW,
            Severity.MEDIUM,
            "Fix one sender before advancing",
            f"{names} is sending as you but isn't DMARC-aligned. Advancing now "
            "would start blocking it. (Confirm it is really you. If it is a spoof, "
            "mark it so and you can advance.)",
            f"Authenticate {names} (SPF include + aligned DKIM), or confirm it "
            "as spoof to dismiss it.",
        )

    # 3. Already fully enforced.
    if idx >= len(LADDER) - 1:
        return Action(
            "AT_GOAL",
            Tier.GOOD,
            Severity.INFO,
            "Fully protected (p=reject, 100%)",
            "Every legitimate sender is aligned and you're at full enforcement. "
            "Spoofed mail is rejected outright.",
            "Keep monitoring for new senders; nothing else to do.",
        )

    # 4. Nothing is failing, so name the next rung.
    #
    # There used to be two gates here: a message count and a 21 day clean
    # streak. Both assumed a service was collecting reports and could count
    # toward a target. Nothing collects now, so the gates only ever told a user
    # to come back later, and the advice promised a reminder that no part of
    # this can send. The caution behind them is real, so it is stated for the
    # reader to weigh rather than enforced with a counter.
    nxt_p, nxt_pct = LADDER[idx + 1]
    label = (
        "monitor only"
        if nxt_p == "none"
        else (f"{nxt_p}" + (f" at {nxt_pct}%" if nxt_pct < 100 else " at 100%"))
    )
    return Action(
        "ADVANCE",
        Tier.GOOD,
        Severity.LOW,
        f"Nothing is failing. The next step is {label}",
        f"Every sender in these reports is authenticated, across "
        f"{summary.total_volume} message(s). A report only shows what sent while "
        f"it was being written, so anything that did not send is simply absent "
        f"here, and that is what breaks when the policy tightens. Make sure you "
        f"recognise this list as how you really send.",
        f"When you recognise every sender above, update your DMARC record to {label}.",
        new_record=_build_record(nxt_p, nxt_pct, rua, current=rec),
    )


# ----------------------------------------------------------------------------
# Orchestration: one call -> everything the UI needs
# ----------------------------------------------------------------------------
def evaluate(rec: DmarcRecord, spf: SpfRecord, summary: ReportSummary, rua: str) -> EngineResult:
    spf_out = spf_findings(spf, summary.senders)
    ladder = dmarc_decision(rec, summary, rua)
    blockers = [s for s in summary.senders if _is_blocker(s)]

    # Primary action = the single most urgent thing. A HIGH spf finding (e.g. a
    # blocking PermError, or a sender that fails DMARC) outranks a routine
    # ladder "advance/hold", because you fix breakage before tightening policy.
    high_spf = [f for f in spf_out if f.severity == Severity.HIGH]
    if ladder.code in ("ROLLBACK", "FIX_SENDER", "PUBLISH_INITIAL"):
        primary = ladder
    elif high_spf:
        primary = high_spf[0]
    else:
        primary = ladder

    return EngineResult(
        primary=primary,
        spf_findings=spf_out,
        ladder_decision=ladder,
        blockers=blockers,
    )
