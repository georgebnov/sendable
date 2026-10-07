"""Campaign Monitor profile."""

from ._profile import ProfileSpec

SPEC = ProfileSpec(
    name="Campaign Monitor",
    vendor_headers=(
        "x-cmail-trackid",
        "x-cm-envelope",
        "x-cmail-mailing-id",
    ),
    feedback_id_tokens=("createsend", "campaignmonitor"),
    signing_domains=(
        "createsend.com",
        "cmail1.com",
        "cmail2.com",
        "cmail19.com",
        "cmail20.com",
    ),
    chrome_markers=(
        "createsend.com",
        "campaignmonitor.com",
    ),
    unsubscribe_host_markers=("createsend.com",),
    support_url="https://help.campaignmonitor.com/",
)
