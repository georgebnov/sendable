"""HubSpot profile."""

from ._profile import ProfileSpec

SPEC = ProfileSpec(
    name="HubSpot",
    vendor_headers=(
        "x-hs-cid",
        "x-hubspot-test",
    ),
    feedback_id_tokens=("hubspot",),
    signing_domains=(
        "hubspotemail.net",
        "hubspotemail-eu1.net",
        "hubspotlinks.com",
    ),
    chrome_markers=(
        "hubspotemail",
        "hubspotlinks.com",
    ),
    unsubscribe_host_markers=("hubspotemail",),
    support_url="https://knowledge.hubspot.com/",
)
