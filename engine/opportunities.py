"""Ways to be recognised in the inbox, which are not defects in the message.

The audit scores what is wrong with an email. A missing logo or a missing
profile picture is not wrong: the message is fine and it would simply do better
with a face beside the sender name. Scoring them would mark a correct email
down, and a sixth weight in the scorer would re-grade every email ever graded,
so these sit beside the findings and never touch the score.

Two of them, cheapest first.

The profile picture is free, takes a few minutes, and applies to mail already
sent. Nothing in a message reveals whether it is set, so the audit cannot rule
it out and always offers it.

A logo record, BIMI, is the official route and the audit can read it, so its
state comes from what the DNS checks already found. It needs an enforcing
policy, and the receiver most people care about charges for the certificate
that goes with it.
"""

from __future__ import annotations

from dataclasses import replace

from .free_mailbox import is_free_mailbox
from .report import Finding, Opportunity

# The picture a recipient sees beside your name in Gmail comes from a Google
# Account registered to the address you send from. It does not need a Gmail
# mailbox, which is the part almost everyone gets wrong.
_PROFILE_PICTURE = Opportunity(
    id="inbox_presence.profile_picture",
    title="Put your face beside your name in Gmail",
    state="available",
    detail=(
        "Gmail shows a picture next to the sender name when the sending address "
        "has a Google Account with a photo on it. It is free, it takes a few "
        "minutes, and it applies to mail you already sent as well as mail you "
        "send next. Only people reading in Gmail see it."
    ),
    steps=[
        "Go to the Google Account sign-up page and choose the option to use an "
        "existing email address. Do not let it give you a new address ending in "
        "gmail.com.",
        "Enter the address you send your mail from, whoever hosts it, and "
        "confirm the code Google sends to it.",
        "Open the account's profile page and upload a photo. A square image of "
        "at least 250 by 250 pixels, as a JPEG or a PNG.",
        "Set who can see the photo to anyone. A photo nobody can see is a photo "
        "Gmail will not show.",
        "Wait. It can take a day to appear.",
        "If you ever open Gmail with this account it will offer to add an "
        "address ending in gmail.com, and the page can read like a warning. "
        "That is normal. Click away from it. You need the account, not a "
        "mailbox, and your mail stays exactly where it is now.",
    ],
)


# A sender already on a Google mailbox has the account. Telling them to sign up
# with an existing address, and to confirm a code sent to it, describes a path
# they cannot take, and the warning about declining a gmail.com address is about
# the address they already use.
_GOOGLE_MAILBOXES = frozenset({"gmail.com", "googlemail.com"})

_PICTURE_STEPS_FOR_A_GOOGLE_MAILBOX = [
    "You already have the account, so there is nothing to create. Open your "
    "Google account's profile page and upload a photo. A square image of at "
    "least 250 by 250 pixels, as a JPEG or a PNG.",
    "Set who can see the photo to anyone. A photo nobody can see is a photo Gmail will not show.",
    "Wait. It can take a day to appear.",
]


def _bimi(findings: list[Finding]) -> Opportunity | None:
    """The logo record, when the audit actually looked at the domain.

    Returns None when there is no BIMI finding, which happens offline and
    whenever the domain checks are skipped. Guessing would be worse than
    silence: it would send a sender to buy a certificate their own policy
    makes useless.
    """
    found = next((f for f in findings if f.check == "bimi.published"), None)
    if found is None:
        return None

    # A lookup that did not answer tells us nothing about the domain. Without
    # this, a timeout on _dmarc.<domain> read as `eligible=False, policy=None`
    # and the advice announced "Your DMARC policy is p=none" to a domain that
    # may well publish p=reject.
    if found.details.get("dns_error"):
        return None

    policy = found.details.get("dmarc_policy")
    eligible = bool(found.details.get("eligible"))

    detail = (
        "A logo record puts your own logo beside your name, and it is the "
        "official route rather than a personal photo. Gmail asks for a paid "
        "certificate to go with it, renewed every year, and the cheaper kind "
        "still needs a mark someone can verify. Apple Mail wants the dearer "
        "kind and takes nothing less. Yahoo, Fastmail and AOL show the logo "
        "with no certificate at all. The profile picture above costs nothing "
        "and reaches Gmail, so do that first and treat this as the step after it."
    )

    if found.passed:
        return Opportunity(
            id="inbox_presence.bimi",
            title="Your logo record is published",
            state="done",
            detail=detail,
            steps=[
                "Check the logo still loads over https, because a receiver that "
                "cannot fetch it shows nothing.",
                "If you want the logo in Gmail, check the certificate has not "
                "expired. They run for a year.",
            ],
        )

    if not eligible:
        return Opportunity(
            id="inbox_presence.bimi",
            title="A logo record, once your policy is stricter",
            state="blocked",
            detail=detail,
            blocked_by=(
                f"Your DMARC policy is p={policy or 'none'}. A receiver ignores a "
                "logo record until the policy is quarantine or reject, so "
                "publishing one now does nothing."
            ),
            steps=[
                "Move your DMARC policy to quarantine, then to reject, checking "
                "your reports in between so nothing of yours starts bouncing.",
                "Then come back to this.",
                "Meanwhile the profile picture above works today and costs nothing.",
            ],
        )

    return Opportunity(
        id="inbox_presence.bimi",
        title="Add a logo record",
        state="available",
        detail=detail,
        steps=[
            "Make a square version of your logo as an SVG, in the plain flavour "
            "a receiver accepts, under 32 kilobytes, and put it somewhere that "
            "serves it over https.",
            "Buy a certificate if you want the logo in Gmail or Apple Mail. "
            "Without one, Yahoo, Fastmail and AOL still show it.",
            "Add a TXT record at default._bimi on your domain pointing at the "
            "logo, and at the certificate when you have one.",
            "Send yourself a message and look at it in Gmail, Yahoo and Apple "
            "Mail. They do not all behave the same way.",
        ],
    )


def opportunities_from(findings: list[Finding], from_addr: str | None = None) -> list[Opportunity]:
    """Everything worth offering, cheapest and most certain first."""
    picture = _PROFILE_PICTURE
    if is_free_mailbox(from_addr) in _GOOGLE_MAILBOXES:
        picture = replace(picture, steps=_PICTURE_STEPS_FOR_A_GOOGLE_MAILBOX)
    items = [picture]
    bimi = _bimi(findings)
    if bimi is not None:
        items.append(bimi)
    return items


__all__ = ["Opportunity", "opportunities_from"]
