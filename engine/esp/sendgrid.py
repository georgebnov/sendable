"""SendGrid profile.

Note: Kit and many SaaS apps route through SendGrid. The cascade in
`_detect.py` is ordered so that a more specific match (Kit's `:CK`
suffix, Klaviyo's vendor header) wins before the generic SendGrid
fallback fires.
"""

from ._profile import ProfileSpec

SPEC = ProfileSpec(
    name="SendGrid",
    vendor_headers=(
        "x-sg-eid",
        "x-sg-id",
        "x-sendgrid-test",
    ),
    feedback_id_tokens=("sendgrid",),
    signing_domains=(
        "sendgrid.net",
        "sendgrid.info",
    ),
    chrome_markers=("sendgrid.net",),
    unsubscribe_host_markers=("sendgrid.net",),
    support_url="https://support.sendgrid.com/",
)
