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

from engine.dmarc.classifier import classify_record
from engine.dmarc.esp_fingerprint import classify as classify_ip
from engine.dmarc.parser import DmarcRecord as ParsedRecord
from engine.dmarc.parser import DmarcReport
from engine.dmarc.policy_engine import Sender, Window

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
        parts = auth.domain.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else auth.domain
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


def _aligned(auths: list, domain: str, *, exact: bool) -> bool:
    """Did any auth result pass on this domain.

    DKIM alignment in relaxed mode compares organizational domains, which for the
    shapes seen in reports means an exact match on the registrable domain. SPF
    alignment accepts a subdomain, because a provider commonly sends as
    mail.example.com on behalf of example.com.
    """
    target = domain.lower()
    for auth in auths:
        if auth.result != "pass" or not auth.domain:
            continue
        got = auth.domain.lower()
        if got == target or (not exact and got.endswith(target)):
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
    days: set[str] = set()
    total_volume = 0

    for report in reports:
        day = report.date_end.strftime("%Y-%m-%d") if report.date_end else None
        begin = report.date_begin.strftime("%Y-%m-%d") if report.date_begin else None
        if day:
            days.add(day)

        for record in report.records:
            verdict = classify_record(
                record, report.policy, known_providers=known_providers
            ).classification
            bucket = _Bucket(
                name=_sender_name(record, verdict),
                volume=record.count,
                # Relaxed DKIM alignment compares the organizational domain.
                dkim_aligned=_aligned(record.auth_dkim, domain, exact=True),
                # SPF alignment accepts a sending subdomain.
                spf_aligned=_aligned(record.auth_spf, domain, exact=False),
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
    has_blocker = any((not s.dmarc_aligned) and s.legitimacy != "suspicious" for s in senders)
    return Window(
        senders=senders,
        clean_streak_days=0 if has_blocker else len(days),
        days_with_data=len(days),
        total_volume=total_volume,
    )


__all__ = [
    "WINDOW_DAYS",
    "build_window",
    "include_for_provider",
    "legitimacy_from_classification",
]
