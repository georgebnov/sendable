"""Turn a pile of DMARC aggregate reports into one picture of who sends for you.

A DMARC aggregate report is an XML file a receiving provider mails you once a day.
It lists every source IP that sent mail claiming to be your domain during one
reporting period, how many messages each sent, and whether SPF and DKIM passed and
aligned. One report is one receiver's snapshot.

The question a sender actually has spans all of them: across everything I received
recently, who sends for me, which of them are failing, and is it safe to tighten
my DMARC policy yet. `build_window` answers that, and `policy_engine.evaluate`
reads the answer to decide the next step.

Three rules decide what the summary says.

Alignment, not authentication. SPF or DKIM passing is not enough. DMARC asks
whether the domain that passed is *your* domain. A provider that signs with its
own key passes DKIM and still fails DMARC, which is the most common real failure.

Best case per flag, across reports. One receiver may report a failure another did
not see, usually because it caught a forwarded copy. A sender that aligned
anywhere is configured correctly, so a later report must not reset the flag.

Worst case for legitimacy. If any report classified a source as a spoof, it is
treated as a spoof. A recognised sender that fails alignment is neither a spoof
nor clean: it is "unconfirmed", which blocks policy advancement until it is fixed,
because tightening policy would start rejecting that sender's real mail.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from engine.copywriting.link_quality import _registrable
from engine.dmarc.classifier import classify_record
from engine.dmarc.esp_fingerprint import classify as classify_ip
from engine.dmarc.parser import DmarcRecord as ParsedRecord
from engine.dmarc.parser import DmarcReport
from engine.dmarc.policy_engine import _UNCONTROLLABLE_TAGS as _UNCONTROLLABLE
from engine.dmarc.policy_engine import Sender, Window

# How harshly a receiver acted, worst last. A merge keeps the worst, because a
# sender being rejected anywhere is being rejected.
_DISPOSITION_RANK = {"none": 0, "quarantine": 1, "reject": 2}

# The trailing period the summary covers. 21 days is long enough that a weekly
# sender appears more than once, and short enough that a fix shows up quickly.
WINDOW_DAYS = 21

# Classifier verdicts that mean "this is your mail, working as intended".
_LEGIT = frozenset(
    {
        "clean",
        "esp_softfail_ok",
        "forwarding_artifact",
        "new_legit_esp",
        "gateway_relay",
        "dkim_temperror",
        "policy_override_arc",
        "policy_override_fwd",
        "policy_override_sampled",
        "policy_override_mailing_list",
        # A bounce notification is neutral. Treating it as legit keeps it out of
        # the blocker list, where it would look like a configuration problem.
        "bounce",
    }
)

# Classifier verdicts that mean someone else is sending as you.
_SUSPICIOUS = frozenset({"spoofing_blocked", "spoofing_delivered"})

# Provider display name to its real SPF include.
#
# Only entries that are verified. A wrong include breaks the sender's mail, so a
# provider that is not in this map returns None and the advice stays text-only
# rather than handing over a record that would do damage.
_ESP_SPF_INCLUDE: dict[str, str] = {
    "Google Workspace": "include:_spf.google.com",
    "Microsoft 365": "include:spf.protection.outlook.com",
    "SendGrid": "include:sendgrid.net",
    "Amazon SES": "include:amazonses.com",
    "Mailgun": "include:mailgun.org",
    "Mailchimp": "include:servers.mcsv.net",
    "Mandrill (Mailchimp)": "include:spf.mandrillapp.com",
    "Postmark": "include:spf.mtasv.net",
}


def include_for_provider(name: str | None) -> str | None:
    """The verified SPF include for a provider, or None when it is not known.

    None is the safe answer. Guessing an include, or building one from the
    provider's name, produces a record that silently fails to authorise the real
    sending infrastructure.
    """
    return _ESP_SPF_INCLUDE.get(name or "")


def legitimacy_from_classification(verdict: str | None) -> str:
    """Map a classifier verdict onto what it means for policy advancement.

    "unconfirmed" is the important one. A recognised sender that failed alignment
    is not a spoof, so calling it suspicious would alarm the user wrongly. It is
    also not clean, so calling it legit would let the policy tighten and start
    rejecting that sender's real mail. It sits between, and it blocks.
    """
    if verdict in _LEGIT:
        return "legit"
    if verdict in _SUSPICIOUS:
        return "suspicious"
    return "unconfirmed"


def _forwarder_domain(record: ParsedRecord) -> str | None:
    """The registrable domain of the host that forwarded this message.

    A forwarder rewrites the SPF envelope sender to itself, so the useful label
    for a forwarded row is that domain and not the ESP fingerprint of the IP.
    One forwarder usually appears on several IPs, and grouping by the domain
    collapses them into one row.
    """
    for auth in record.auth_spf:
        if not auth.domain:
            continue
        # Use the public-suffix list, not the last two labels. "Last two" turned
        # mail.forwarder.co.uk into "co.uk", so every UK, Australian, and Japanese
        # forwarder collapsed into one row, which is the opposite of the grouping
        # this exists to do.
        return _registrable(auth.domain) or auth.domain
    return None


def _sender_name(record: ParsedRecord, verdict: str | None) -> str:
    """The most informative label available for this source.

    Order: a forwarder or relay the classifier already named, then the ESP
    fingerprint of the IP, then the raw IP. Reverse DNS is deliberately not
    consulted here: a sender controls its own PTR record, so it is a hint rather
    than evidence, and it costs a lookup per unknown IP.
    """
    if verdict == "forwarding_artifact":
        return f"Relay via {_forwarder_domain(record) or 'forwarder'}"

    fingerprint = classify_ip(record.source_ip)
    if verdict == "gateway_relay" and fingerprint.name != "unknown":
        return f"{fingerprint.name} relay"
    if fingerprint.name and fingerprint.name != "unknown":
        return fingerprint.name
    return f"Unknown source {record.source_ip}"


def _aligned(auths: list, domain: str, *, strict: bool) -> bool:
    """Did any auth result pass on a domain that aligns with `domain`.

    DMARC publishes two alignment modes per method, and both default to relaxed:

      strict   the authenticated domain must equal the From domain exactly
      relaxed  they must share an organizational domain, so a subdomain aligns

    Relaxed is the default, and it is what makes an ESP signing `d=em.example.com`
    for `From: @example.com` correctly aligned. Treating that as unaligned told
    the user a working sender was failing DMARC and that they must not tighten
    their policy.

    The comparison is on a label boundary, never a bare string ending. A plain
    `endswith` accepted `notexample.com` as aligned with `example.com`, so a
    spoofer passing SPF on a lookalike read as aligned, dropped out of the blocker
    list, and the engine offered to advance the policy.
    """
    target = domain.lower().rstrip(".")
    target_org = _registrable(target) or target
    for auth in auths:
        if auth.result != "pass" or not auth.domain:
            continue
        got = auth.domain.lower().rstrip(".")
        if got == target:
            return True
        if strict:
            continue
        # Relaxed: compare organizational domains, which is what RFC 7489 means.
        if (_registrable(got) or got) == target_org:
            return True
    return False


@dataclass
class _Bucket:
    """One sender under construction, before it becomes a Sender."""

    name: str
    volume: int = 0
    dkim_aligned: bool = False
    spf_aligned: bool = False
    spf_authpassed: bool = False
    has_dkim_signature: bool = False
    legitimacy: str = "unconfirmed"
    disposition: str = "none"
    esp_include: str | None = None
    classification: str | None = None
    first_seen: str | None = None

    def absorb(self, other: _Bucket) -> None:
        """Merge another bucket in, taking the best case on each alignment flag
        and the worst case on legitimacy."""
        self.volume += other.volume
        self.dkim_aligned = self.dkim_aligned or other.dkim_aligned
        self.spf_aligned = self.spf_aligned or other.spf_aligned
        self.spf_authpassed = self.spf_authpassed or other.spf_authpassed
        self.has_dkim_signature = self.has_dkim_signature or other.has_dkim_signature
        if other.legitimacy == "suspicious":
            self.legitimacy = "suspicious"
        elif self.legitimacy == "unconfirmed" and other.legitimacy == "legit":
            self.legitimacy = "legit"
        # Worst disposition wins. policy_engine gates its most urgent action,
        # "legit mail is being rejected right now", on this field. Keeping
        # whichever report happened to be read first meant a user whose real mail
        # one receiver was rejecting was never told, because another receiver
        # reported the same sender as delivered.
        if _DISPOSITION_RANK.get(other.disposition, 0) > _DISPOSITION_RANK.get(self.disposition, 0):
            self.disposition = other.disposition
            self.classification = other.classification
        if other.first_seen and (self.first_seen is None or other.first_seen < self.first_seen):
            self.first_seen = other.first_seen

    def to_sender(self) -> Sender:
        return Sender(
            name=self.name,
            volume=self.volume,
            dkim_aligned=self.dkim_aligned,
            spf_aligned=self.spf_aligned,
            spf_authpassed=self.spf_authpassed,
            has_dkim_signature=self.has_dkim_signature,
            legitimacy=self.legitimacy,
            disposition=self.disposition,
            esp_include=self.esp_include,
            classification=self.classification,
            first_seen=self.first_seen,
        )


def build_window(
    reports: list[DmarcReport],
    *,
    domain: str,
    known_providers: set[str] | None = None,
) -> Window:
    """Summarise every report into one Window for the policy engine.

    `known_providers` is the set of sender identities seen in earlier reports. With
    it, the classifier can tell a brand new source from one that has sent before,
    which is the difference between "a spoof just started" and "your provider added
    an IP". Without it, new-sender detection is skipped rather than guessed.
    """
    by_key: dict[str, _Bucket] = {}
    days: set[date] = set()
    total_volume = 0

    for report in reports:
        day = report.date_end.date() if report.date_end else None
        begin = report.date_begin.strftime("%Y-%m-%d") if report.date_begin else None
        if day:
            days.add(day)

        # The published alignment tags, which default to relaxed. They were parsed
        # into DmarcPolicyPublished and then never read, so a domain publishing
        # adkim=s was graded as if it had published the default.
        adkim_strict = bool(report.policy and (report.policy.adkim or "r").lower() == "s")
        aspf_strict = bool(report.policy and (report.policy.aspf or "r").lower() == "s")

        for record in report.records:
            verdict = classify_record(
                record, report.policy, known_providers=known_providers
            ).classification
            bucket = _Bucket(
                name=_sender_name(record, verdict),
                volume=record.count,
                dkim_aligned=_aligned(record.auth_dkim, domain, strict=adkim_strict),
                spf_aligned=_aligned(record.auth_spf, domain, strict=aspf_strict),
                spf_authpassed=any(a.result == "pass" for a in record.auth_spf),
                has_dkim_signature=bool(record.auth_dkim),
                legitimacy=legitimacy_from_classification(verdict),
                disposition=record.disposition or "none",
                esp_include=include_for_provider(classify_ip(record.source_ip).name),
                classification=verdict,
                first_seen=begin,
            )
            total_volume += record.count

            # Group by name, so one provider sending from many IPs is one row.
            existing = by_key.get(bucket.name)
            if existing is None:
                by_key[bucket.name] = bucket
            else:
                existing.absorb(bucket)

    senders = [b.to_sender() for b in by_key.values()]

    # The streak counts days with no blocker. A blocker is a sender that failed
    # alignment but is not a spoof: real mail that would start being rejected if
    # the policy tightened now. One anywhere in the window resets it to zero,
    # which is the conservative reading and the one that protects the user.
    # A blocker here means "something I must fix before advancing". A hop on the
    # recipient's side is not that: their gateway, mailing list, or forwarder
    # breaks alignment by design and the sender cannot authenticate it. Counting
    # them held the streak at zero permanently, so no domain whose recipients used
    # a security gateway could ever advance.
    has_blocker = any(
        (not s.dmarc_aligned)
        and s.legitimacy != "suspicious"
        and s.classification not in _UNCONTROLLABLE
        for s in senders
    )

    # The streak is how many days the clean run covers, not how many reports
    # arrived. Counting report-days meant a sender who mails on weekdays, or who
    # loses a day to a provider that skips empty periods or to one unreadable
    # file, could never reach CLEAN_DAYS_REQUIRED and so could never advance. A
    # day with no report is not a dirty day.
    #
    # With a blocker present this stays 0. Working out when the blocker started
    # needs per-day aggregation the summary does not do, and 0 is the answer that
    # protects the user.
    clean_streak_days = 0
    if not has_blocker and days:
        span = (max(days) - min(days)).days + 1
        clean_streak_days = span

    return Window(
        senders=senders,
        clean_streak_days=clean_streak_days,
        days_with_data=len(days),
        total_volume=total_volume,
    )


__all__ = [
    "WINDOW_DAYS",
    "build_window",
    "include_for_provider",
    "legitimacy_from_classification",
]
