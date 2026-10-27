"""Klaviyo profile."""

from ._profile import ProfileSpec

SPEC = ProfileSpec(
    name="Klaviyo",
    vendor_headers=(
        "x-klaviyo-messageid",
        "x-klaviyo",
    ),
    feedback_id_tokens=("klaviyo",),
    signing_domains=(
        "send.klaviyo.com",
        "klaviyomail.com",
        "klaviyo.com",
    ),
    chrome_markers=(
        "klaviyo.com",
        "manage your preferences",
    ),
    unsubscribe_host_markers=("klaviyo.com",),
    support_url="https://help.klaviyo.com/",
)
