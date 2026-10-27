"""Kit (formerly ConvertKit) profile.

Kit routes outbound mail through SendGrid; the giveaway is the `:CK`
suffix on Feedback-ID, the `kit.com` / `convertkit-mail2.com` signing
domains, and the "Built with Kit" badge in the footer. Kit's templates
inject U+200B around the social-icon row, the unsubscribe link, and the
"Powered by Kit" badge — those zero-widths are template chrome, not user
content, so checks that detect them must defer to this profile.
"""

from ._profile import ProfileSpec

SPEC = ProfileSpec(
    name="Kit",
    feedback_id_tokens=(":ck",),
    signing_domains=(
        "kit.com",
        "convertkit-mail2.com",
        "convertkit.com",
        "convertkit-mail.com",
    ),
    chrome_markers=(
        "Built with Kit",
        "Powered by Kit",
        "Powered by ConvertKit",
        "kit.com/unsubscribe",
    ),
    unsubscribe_host_markers=("kit.com", "convertkit"),
    support_url="https://help.kit.com/",
)
