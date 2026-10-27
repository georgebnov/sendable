"""Brevo (formerly Sendinblue) profile."""

from ._profile import ProfileSpec

SPEC = ProfileSpec(
    name="Brevo",
    vendor_headers=(
        "x-mailin-client",
        "x-mailin-campaign",
        "x-sib-id",
    ),
    feedback_id_tokens=("brevo", "sendinblue"),
    signing_domains=(
        "sendinblue.com",
        "brevo.com",
        "sendibm1.com",
        "sendibm3.com",
    ),
    chrome_markers=(
        "sendinblue.com",
        "brevo.com",
    ),
    unsubscribe_host_markers=("sendinblue", "brevo"),
    support_url="https://help.brevo.com/",
)
