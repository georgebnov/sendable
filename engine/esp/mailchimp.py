"""Mailchimp profile."""

from ._profile import ProfileSpec

SPEC = ProfileSpec(
    name="Mailchimp",
    vendor_headers=(
        "x-mailchimp-campaign-id",
        "x-mc-user",
        "x-mailchimp-test",
    ),
    feedback_id_tokens=("mailchimp", "mcusercontent"),
    signing_domains=(
        "mailchimpapp.net",
        "mcsv.net",
        "mcdlv.net",
        "rs6.net",
    ),
    chrome_markers=(
        "View this email in your browser",
        "list-manage.com",
    ),
    unsubscribe_host_markers=("list-manage.com",),
    support_url="https://mailchimp.com/help/",
)
