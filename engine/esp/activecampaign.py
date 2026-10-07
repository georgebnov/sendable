"""ActiveCampaign profile."""

from ._profile import ProfileSpec

SPEC = ProfileSpec(
    name="ActiveCampaign",
    vendor_headers=(
        "x-ac-campaign-id",
        "x-ac-tracker",
    ),
    feedback_id_tokens=("activecampaign", "activehosted"),
    signing_domains=(
        "activehosted.com",
        "activecampaign.com",
        "acemsa1.com",
    ),
    chrome_markers=(
        "activehosted.com",
        "activecampaign.com",
    ),
    unsubscribe_host_markers=("activehosted.com",),
    support_url="https://help.activecampaign.com/",
)
