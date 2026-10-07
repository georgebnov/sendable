"""Human-readable labels for check identifiers.

Audit check IDs like `copywriting.subject_heuristics` or `dkim_record.key_bits`
are stable wire keys — useful for analytics, terrible for UI. This module
maps them to one-line marketer-friendly labels.

When a check isn't in the map we fall back to a smart prettifier that:
  - drops the category prefix
  - replaces underscores with spaces
  - capitalizes the first letter

So `copywriting.something_new` → "Something new" without us having to
add every newly-added check here by hand.
"""

from __future__ import annotations

# Curated labels. Keep these in marketer language — never use jargon
# (DKIM, DMARC, SPF) without explaining what it means in context.
CHECK_LABELS: dict[str, str] = {
    # ─── auth (receiver-reported) ─────────────────────────────────────
    "auth.spf": "Sender authentication (SPF)",
    "auth.dkim": "Signature authentication (DKIM)",
    "auth.dmarc": "Anti-spoofing policy (DMARC)",
    "auth.dmarc_policy_strength": "Anti-spoofing policy strength",
    "auth.bimi": "Logo verification (BIMI)",
    "auth.arc": "Forwarded-mail trust chain (ARC)",
    "auth.authentication_results": "Authentication results header",
    "auth.tls_transport": "Encrypted delivery (TLS)",
    "auth.dmarc_alignment_dkim": "DKIM matches your sending domain",
    "auth.dmarc_alignment_spf": "SPF matches your sending domain",
    "auth.dmarc_alignment_overall": "Overall authentication alignment",
    "auth.reply_to_alignment": "Reply-To matches sending domain",
    "auth.reply_to_monitored": "Reply-To is a real mailbox",
    # ─── DNS records ─────────────────────────────────────────────────
    "spf_record.published": "SPF record published",
    "spf_record.syntax": "SPF record syntax",
    "dmarc_record.published": "DMARC record published",
    "dmarc_record.policy_enabled": "DMARC policy is enforcing",
    "dkim_record.published": "DKIM key published",
    "dkim_record.public_key": "DKIM public key present",
    "dkim_record.key_bits": "DKIM key strength",
    "dkim_record.third_party_signatures": "Third-party signing infrastructure",
    "bimi.published": "Logo record (BIMI) — optional",
    "bimi.syntax": "Logo record syntax",
    "mta_sts.published": "Inbound TLS hardening (MTA-STS) — optional",
    "mta_sts.policy_fetch": "MTA-STS policy reachable",
    "mta_sts.policy_syntax": "MTA-STS policy syntax",
    "mta_sts.syntax": "MTA-STS record syntax",
    "mta_sts.multiple_records": "MTA-STS multiple records",
    "tlsrpt.published": "TLS reporting (TLSRPT) — optional",
    "tlsrpt.syntax": "TLSRPT record syntax",
    # ─── content / hygiene ───────────────────────────────────────────
    "content.subject_present": "Subject line present",
    "content.plain_text_alternative": "Plain-text version included",
    "content.list_unsubscribe_header": "One-click unsubscribe header",
    "content.list_unsubscribe_post": "One-click unsubscribe configured",
    "content.unsubscribe_link_body": "Visible unsubscribe link",
    "content.image_text_ratio": "Image vs text balance",
    "content.body_visible_text_min": "Body has visible text",
    "content.zero_width": "Hidden zero-width characters",
    "content.bidi_override": "Hidden text direction overrides",
    "content.hidden_css_salting": "Hidden text behind CSS",
    "content.homoglyphs": "Look-alike character spoofing",
    "content.url_shortener": "URL shorteners in links",
    "content.empty_href": "Empty link destinations",
    "content.anchor_href_mismatch": "Link text doesn't match URL",
    "content.merge_tag_unfilled": "Merge tags left unfilled",
    # ─── copywriting ─────────────────────────────────────────────────
    "copywriting.subject_word_count": "Subject line length",
    "copywriting.subject_heuristics": "Subject line quality",
    "copywriting.subject_deadwords": "Engagement-killing words in subject",
    "copywriting.subject_body_mismatch": "Subject matches body content",
    "copywriting.preheader_quality": "Preview text quality",
    "copywriting.preheader_repeats_subject": "Preview text repeats subject",
    "copywriting.body_length": "Body length",
    "copywriting.long_paragraph": "Paragraphs too long",
    "copywriting.body_shouting": "ALL-CAPS shouting in body",
    "copywriting.reading_level": "Reading-level difficulty",
    "copywriting.single_big_idea": "Multiple competing ideas",
    "copywriting.benefit_over_feature": "Lead with benefit, not feature",
    "copywriting.curiosity_hook": "Opening hook strength",
    "copywriting.social_proof_presence": "Social proof present",
    "copywriting.generic_opener": "Generic 'I hope this finds you' opener",
    "copywriting.personal_from_name": "Personal name in From line",
    "copywriting.from_name_body_consistency": "From name matches body voice",
    "copywriting.spam_trigger": "Spam-trigger words",
    "copywriting.urgency_position": "Urgency phrasing position",
    "copywriting.doubt_creation": "Doubt-creating phrasing",
    "copywriting.cta_count": "Number of calls-to-action",
    "copywriting.cta_outcome_copy": "Call-to-action wording",
    "copywriting.link_count": "Link density",
    "copywriting.emoji_count": "Emoji count",
    "copywriting.body_newsletter_word": "Body contains 'newsletter' word",
    "copywriting.fake_reply_subject": "Fake 'Re:' in subject",
    "copywriting.compound_signal": "Stacked promotional signals",
    "copywriting.voice_consistency": "Voice consistency",
    "copywriting.ai_writing_pattern": "AI-pattern phrasing detected",
    "copywriting.drive_link": "Google Drive / Dropbox link",
    # ─── infra / delivery ────────────────────────────────────────────
    "blacklist.sender_ip_extraction": "Sender IP detected",
    "blacklist.skipped_esp": "Blocklist skipped (known ESP IP)",
    "delivery.spam_folder": "Delivered to Spam folder",
    "smtp.dns_resolution": "Sender host resolves",
    "smtp.managed_operator": "Sending via managed operator",
    "smtp.mx_bare_ip": "MX uses bare IP (not allowed)",
    "smtp.mx_cname_violation": "MX points at a CNAME (not allowed)",
    "smtp.null_mx": "Null MX (domain doesn't accept mail)",
    "smtp.open_relay": "Open relay (security risk)",
    # ─── headers ─────────────────────────────────────────────────────
    "headers.feedback_id": "Feedback-ID header for reputation",
    "headers.precedence_bulk": "Precedence: bulk header",
    "headers.template_test_send": "Template / test-send marker",
    # ─── render / size ───────────────────────────────────────────────
    "render.unsub_clipped": "Unsubscribe link clipped by Gmail",
    "size.html_present": "HTML version present",
    "size.html_bytes": "HTML size (Gmail clip threshold)",
    # ─── drift (history-derived) ─────────────────────────────────────
    "drift.d01_dmarc_regression": "Authentication regression",
    "drift.d03_auth_flip": "Authentication result flipped",
    "drift.d04_dmarc_policy_downgrade": "Anti-spoofing policy weakened",
    "drift.d08_list_unsub_regression": "Unsubscribe header regression",
    "drift.d10_display_name_rotation": "Sender display name changed",
    "drift.d11_reply_to_divergence": "Reply-To changed unexpectedly",
}


def label_for(check: str) -> str:
    """Look up a friendly label; fall back to a prettified key.

    Fallback drops the category prefix and converts snake_case to a
    sentence-case phrase. So a brand-new check like
    'copywriting.something_clever' renders as 'Something clever' until
    someone adds it to the curated map.
    """
    if check in CHECK_LABELS:
        return CHECK_LABELS[check]
    _, _, tail = check.partition(".")
    if not tail:
        tail = check
    return tail.replace("_", " ").capitalize()
