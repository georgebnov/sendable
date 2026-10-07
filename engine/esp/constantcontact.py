"""Constant Contact profile."""

from ._profile import ProfileSpec

SPEC = ProfileSpec(
    name="Constant Contact",
    vendor_headers=(
        "x-cc-mailid",
        "x-mc-cc",
    ),
    feedback_id_tokens=("constantcontact",),
    signing_domains=(
        "ccsend.com",
        "in.constantcontact.com",
        "constantcontact.com",
    ),
    chrome_markers=(
        "constantcontact.com",
        "ccsend.com",
    ),
    unsubscribe_host_markers=("constantcontact.com", "ccsend.com"),
    support_url="https://knowledgebase.constantcontact.com/",
)
