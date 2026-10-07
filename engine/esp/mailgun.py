"""Mailgun profile."""

from ._profile import ProfileSpec

SPEC = ProfileSpec(
    name="Mailgun",
    vendor_headers=(
        "x-mailgun-sending-ip",
        "x-mailgun-track",
        "x-mailgun-variables",
    ),
    feedback_id_tokens=("mailgun",),
    signing_domains=(
        "mailgun.org",
        "mailgun.info",
        "mg.mailgun.com",
    ),
    chrome_markers=("mailgun.org",),
    unsubscribe_host_markers=("mailgun",),
    support_url="https://help.mailgun.com/",
)
