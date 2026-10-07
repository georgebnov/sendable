"""LLM-powered humanization of an audit Report.

Takes the deterministic `Report` and produces a `HumanizedReport` with a
plain-English executive summary and a list of actionable issues. The LLM
never carries the verdict — that was set deterministically by
audit/severity.py. The prose layer only translates.

Design rules:
 - Skip the LLM call entirely when nothing failed (clean audit → no summary).
 - Skip silently if OPENAI_API_KEY is missing or the call fails. Callers
   render the technical breakdown without a summary.
 - Send failing findings + email context (subject, body excerpt, inferred
   tool) so the LLM can cite specific content, not generic advice.
 - Uses `openai.beta.chat.completions.parse` with response_format=Pydantic
   for strict structured output — no JSON parsing / validation headaches.
"""

from __future__ import annotations

import os
import re
import sys

from dotenv import load_dotenv

from .parse import ParsedEmail
from .report import Finding, HumanizedReport, Report

load_dotenv()  # reads project-root .env for OPENAI_API_KEY

_MODEL = "gpt-4o-mini"
_BODY_EXCERPT_CHARS = 600

_SYSTEM_PROMPT = """\
You are an email deliverability coach. You translate a deterministic email-audit
report into plain English for a marketer or small-business owner who sends their
own newsletter via a tool like Kit (ConvertKit), Mailchimp, HubSpot, Klaviyo,
ActiveCampaign, or SendGrid.

Your reader is NOT technical. They do not know what DMARC, DKIM, SPF, RFC 8058,
CSS, or "zero-width character" means, and critically they DO NOT SEE THEIR
EMAIL'S HTML. They see a composer in their tool with fields like "subject",
"preview text / preheader", "body editor", "link URL", and settings.

NEVER mention these terms in `whats_wrong` or `what_to_do`: div, span, table,
img, tag, element, attribute, HTML, CSS, display:none, font-size:0, opacity:0,
mso-hide, selector, MIME, multipart, text/html, text/plain, header (as in
email header), Return-Path, envelope, RFC, standard, specification.

Describe every fix in terms of composer actions: "clear the preview-text field",
"edit the link's URL in the body", "retype the subject line", "in your email
tool's settings, toggle X", "contact your email-tool's support". If a fix
requires the user to understand HTML or CSS, they CANNOT do it themselves —
categorize as 'workaround' and describe what a normal user can try ("check if
your preview-text field has anything unusual in it"), not what an engineer
would do.

Do NOT call their tool an "ESP." Say "email sending tool", "your Mailchimp
composer", "Kit's editor", etc., naming the tool if you can infer it from the
From address, headers, or details.

CRITICAL RULES:
 1. Every issue object's `check` field must EXACTLY match the `check`
    identifier of one of the failing findings in the provided list. This
    is how location citations are matched to your prose. Do not invent
    check names; copy them verbatim from the input.

    Location citations are generated deterministically by the code, NOT by
    you — do not try to describe where the problem is inside `whats_wrong`
    or `what_to_do`. Focus only on what the problem is and what the reader
    should do about it.

 2. Every `user_can_fix` field must be one of three values and must reflect
    REALITY. Here is the definitive mapping by check identifier — use it:

       'yes' (user can fix USING ONLY their email tool's composer — subject
       line, link URLs, body text as typed into the editor):
         - content.homoglyphs (user edits the link URL or subject line in
           their composer to use regular Latin letters)
         - content.zero_width and content.bidi_override when the characters
           appear in the subject line, which the user can retype
         - content.unsubscribe_link_body (user adds an unsubscribe link in
           the body editor)
         - content.image_text_ratio (user writes more body text or removes
           images in the composer)
         - content.url_shortener, content.anchor_href_mismatch (user edits
           link URLs or visible link text in the composer)
         - size.html_bytes, render.unsub_clipped (user shortens their email
           in the composer)
         - drift.d10_display_name_rotation, drift.d11_reply_to_divergence
           (user controls sender name / Reply-To from their email tool's
           profile or settings)
         - copywriting.subject_heuristics (user retypes the subject line in
           the composer — shorter, sentence case, one idea)
         - copywriting.spam_trigger (user rephrases the flagged phrase in
           subject/body — e.g. "Reserve Your Unit" → "If you want the
           details, just reply"; "Starting From $899K" → "pricing's landing
           in the high $800s" or move absolute figure to a reply)
         - copywriting.compound_signal (user rewrites the email to drop the
           promotional stack — fewer urgency/FOMO/commerce/financial cues;
           one idea, one CTA, relative pricing not datasheet pricing)
         - copywriting.body_length (user trims the body in the composer)
         - copywriting.link_count (user removes extra links in the composer)
         - copywriting.drive_link (user replaces the Google-Drive link with
           a hosted page on their own domain, or offers the file by reply)
         - copywriting.emoji_count (user edits emoji out of subject/body)
         - copywriting.body_newsletter_word (user removes the word
           "newsletter" from the body)
         - copywriting.body_shouting (user retypes ALL-CAPS lines in the
           body editor as normal sentence case, trims excessive
           exclamation marks — "BUY THIS COURSE!" → "The new course is
           here if you want a look.")

       'workaround' (the email sending tool, its template, or its renderer
       is doing this — the user CANNOT fix it by editing the composer's
       normal fields):
         - content.hidden_css_salting — ALWAYS workaround for the audience
           we serve. Marketers using Kit / Mailchimp / HubSpot never see
           their email's HTML source; hidden content is injected by the
           tool's template (preheader spans, tracking pixels, show/hide
           rules). Even when the hidden content looks adversarial, the
           marketer did not hand-write the div — the tool did — so the
           workaround is to check the preview-text field, look for any
           stray text above the greeting in preview mode, or contact the
           tool's support. Never tell them to "remove the div."
         - content.zero_width when the detail.locations show the characters
           are in body HTML (around styled link paragraphs, footer
           boilerplate, etc.) — the sending tool injects them.
         - content.list_unsubscribe_header, content.list_unsubscribe_post —
           the user cannot hand-edit email headers; their sending tool emits
           them. Workaround: toggle a setting in the tool (e.g., "enable
           one-click unsubscribe").
         - content.plain_text_alternative — the tool generates this from the
           HTML; user enables a setting.
         - headers.feedback_id — tool-level configuration.

       'infrastructure' (DNS / domain authentication, NOT email content):
         - auth.spf, auth.dkim, auth.dmarc — missing or failing
         - drift.d01_dmarc_regression, drift.d03_auth_flip,
           drift.d04_dmarc_policy_downgrade — regression in domain auth

    NEVER mark a content-side check as 'infrastructure'.

 3. For 'workaround' issues, explicitly tell the reader the tool is doing
    this automatically, describe the workaround, AND tell them it's okay to
    accept the penalty if restructuring is too hard — the severity tells them
    how much it matters.

 4. Never invent facts. Only say what the report, details, and body excerpt
    support. If you don't know which tool the sender uses, don't guess.

 5. Order issues by severity: CRITICAL before HIGH before MEDIUM before LOW.
"""

_USER_PROMPT_TEMPLATE = """\
Here is an email audit report. Produce a one-sentence executive summary and a
plain-English breakdown of each failing finding.

## Report metadata
- Score: {score}/100
- Verdict: {verdict}
- From: {from_addr}
- Subject: {subject}
- Drift history: {history_desc}
- Likely email tool (inferred from headers): {tool_hint}

## Email body excerpt (first {excerpt_chars} chars of the text/plain part)
```
{body_excerpt}
```

## Failing findings (full details including exact locations)
{findings_json}
"""


def format_location(finding: Finding) -> str:
    """Deterministic 'where' citation for a finding. Pulled from finding.details
    with no LLM involvement — citation accuracy is too important to delegate
    to a language model.
    """
    check = finding.check
    d = finding.details or {}

    # Hidden-CSS salting: details.hits[*].tag / text_preview / selector
    # Prose is marketer-facing: never name HTML tags or CSS selectors; these
    # go in the Technical breakdown section for developers.
    if check == "content.hidden_css_salting":
        hits = d.get("hits") or []
        if hits:
            h = hits[0]
            preview = (h.get("text_preview") or "").strip()
            n_more = len(hits) - 1
            extra = f" (+{n_more} more)" if n_more > 0 else ""
            if preview:
                truncated = preview[:120] + ("…" if len(preview) > 120 else "")
                return f'hidden content in your email reading "{truncated}"{extra}'
            return f'a hidden piece of content in your email with no readable text{extra}'

    # Invisible chars — strip the "body (html) @ char N:" prefix and the
    # «U+XXXX» developer marker. Leave the surrounding text so the user can
    # search for it in their composer.
    if check in ("content.zero_width", "content.bidi_override"):
        locations = d.get("locations") or []
        if locations:
            n = d.get("count") or len(locations)
            raw = str(locations[0])
            # Strip "body (html) @ char NNN:" / "subject @ char NNN:" prefix
            cleaned = re.sub(r"^[^:]+@\s*char\s*\d+\s*:\s*", "", raw)
            # Replace developer codepoint markers with plain-English label
            cleaned = re.sub(r"«U\+[0-9A-Fa-f]+»", "[invisible character]", cleaned)
            # Kill the newline marker used in developer output
            cleaned = cleaned.replace("↵", " ").strip()
            more = f" (and {n - 1} more like this)" if n > 1 else ""
            return f'near the text: "{cleaned}"{more}'
        return "in the body text — location not recorded"

    # Homoglyphs: details.hits[*].{where, char, alias, source}
    if check == "content.homoglyphs":
        hits = d.get("hits") or []
        if hits:
            h = hits[0]
            where_field = h.get("where") or ""
            char = h.get("char") or ""
            alias = h.get("alias") or ""
            source = (h.get("source") or "").strip()
            n_more = len(hits) - 1
            extra = f" (+{n_more} more)" if n_more > 0 else ""
            if where_field == "link_href":
                if source:
                    return f"the link pointing to `{source}` — contains a {alias} character '{char}' that looks like a Latin letter{extra}"
                return f"in a link URL — a {alias} character '{char}' that looks like a Latin letter{extra}"
            if where_field == "subject":
                if source:
                    return f"in the subject line \"{source}\" — a {alias} character '{char}'{extra}"
                return f"in the subject line — a {alias} character '{char}'{extra}"
            if where_field == "body" and source:
                snippet = source[:120] + ("…" if len(source) > 120 else "")
                return f"in the body text starting \"{snippet}\" — a {alias} character '{char}'{extra}"
            return f"in the {where_field} — a {alias} character '{char}'{extra}"

    # URL shorteners
    if check == "content.url_shortener":
        hits = d.get("hits") or []
        if hits:
            hosts = [h.get("host") for h in hits[:3] if h.get("host")]
            if hosts:
                return f"link(s) routed through shortener domain(s): {', '.join(hosts)}"

    # Anchor-href mismatch
    if check == "content.anchor_href_mismatch":
        hits = d.get("hits") or []
        if hits:
            h = hits[0]
            return (
                f"link text shows '{h.get('visible_domain')}' but href goes to "
                f"'{h.get('href_registrable')}'"
            )

    # Image-to-text ratio
    if check == "content.image_text_ratio":
        return (
            f"your email has {d.get('image_count')} image(s) but only "
            f"{d.get('visible_chars')} characters of visible text "
            f"(we recommend at least {d.get('text_floor')})"
        )

    # Clipped unsubscribe
    if check == "render.unsub_clipped":
        return (
            "your unsubscribe link sits too far down in the email — Gmail "
            "will cut it off before the reader scrolls to it"
        )

    # Size — express in KB, not bytes
    if check == "size.html_bytes":
        b = d.get("bytes")
        lim = d.get("limit")
        if b:
            if lim:
                return f"your email is {b // 1024} KB (limit is {lim // 1024} KB)"
            return f"your email is {b // 1024} KB"

    # Drift — D10 display-name rotation
    if check == "drift.d10_display_name_rotation":
        if d.get("new_name"):
            return (
                f"new display name '{d['new_name']}' not seen in last "
                f"{d.get('rows')} sends"
            )
        if d.get("churn_ratio") is not None:
            return (
                f"{d.get('distinct_count')} distinct display names across "
                f"{d.get('rows')} sends (churn {d['churn_ratio']:.0%})"
            )

    # Drift — D11 Reply-To
    if check == "drift.d11_reply_to_divergence":
        if d.get("current"):
            return f"Reply-To changed to '{d['current']}' (not seen before)"

    # Drift — auth regressions, all share (current, prior_results, last10, etc.)
    if check.startswith("drift.") and "dmarc" in check:
        if d.get("current"):
            return f"current DMARC result: {d['current']}"

    # Copywriting checks — cite the specific subject, phrase, or field
    if check == "copywriting.subject_heuristics":
        subj = d.get("subject") or ""
        if subj:
            snippet = subj[:80] + ("…" if len(subj) > 80 else "")
            return f"in the subject line \"{snippet}\""
        return "in the subject line"
    if check == "copywriting.spam_trigger":
        phrase = d.get("phrase")
        field = d.get("field")
        if phrase and field:
            return f"the phrase \"{phrase}\" in the {field}"
    if check == "copywriting.compound_signal":
        cats = d.get("categories") or []
        if cats:
            return f"across the email — {len(cats)} promotional signal categories stacking ({', '.join(cats)})"
    if check == "copywriting.body_length":
        wc = d.get("word_count")
        if wc:
            return f"body is {wc} words — readers bail past ~250 words"
    if check == "copywriting.link_count":
        n = d.get("count")
        wc = d.get("word_count")
        budget = d.get("link_budget")
        if n and wc and budget:
            return (
                f"{n} links across {wc} words — exceeds the ~1-link-per-125-words "
                f"newsletter ratio (budget {budget})"
            )
        if n:
            return f"{n} links in the body"
    if check == "copywriting.drive_link":
        url = d.get("url")
        if url:
            return f"the Google Drive link `{url}` in the body"
    if check == "copywriting.emoji_count":
        n = d.get("count")
        if n:
            return f"{n} emoji across subject + body (cap is 1)"
    if check == "copywriting.body_newsletter_word":
        return "the word 'newsletter' appears in the body"
    if check == "copywriting.body_shouting":
        lines = d.get("lines") or []
        if lines:
            first = lines[0]
            more = f" (and {len(lines) - 1} more)" if len(lines) > 1 else ""
            return f"in the body line \"{first}\"{more}"
        n = d.get("count")
        if n:
            return f"{n} exclamation marks in the body"

    # Header-level / tool-configuration checks — nothing in the body to cite.
    if check in {
        "auth.spf", "auth.dkim", "auth.dmarc", "auth.authentication_results",
        "auth.arc", "auth.bimi",
        "content.list_unsubscribe_header", "content.list_unsubscribe_post",
        "content.plain_text_alternative",
        "content.unsubscribe_link_body",
        "headers.feedback_id",
        "drift.d03_auth_flip",
        "drift.d04_dmarc_policy_downgrade",
        "drift.d08_list_unsub_regression",
    }:
        return "in your email tool's settings or your domain setup — not in the email body"

    # Fallback: dump the raw details key set so it's never silent.
    if d:
        keys = ", ".join(f"{k}={v!r}" for k, v in list(d.items())[:3])
        return f"(details: {keys})"
    return ""


def _infer_tool(email: ParsedEmail) -> str:
    """Best-guess the sending tool from headers, for the LLM's context. Never
    100% certain; don't surface this in the report, just hint to the LLM."""
    hints = []
    feedback_id = (email.headers.get("feedback-id") or [""])[0].lower()
    if "hubspot" in feedback_id:
        hints.append("HubSpot")
    if "sendgrid" in feedback_id or "sendgrid" in (email.headers.get("x-sg-id") or [""])[0].lower():
        hints.append("SendGrid")
    if "mailchimp" in feedback_id or email.headers.get("x-mailchimp-campaign-id"):
        hints.append("Mailchimp")
    if email.headers.get("x-klaviyo-messageid"):
        hints.append("Klaviyo")
    if email.headers.get("x-ac-campaign-id"):
        hints.append("ActiveCampaign")
    # ConvertKit (Kit) routes through SendGrid with CK in feedback-id
    if feedback_id.endswith(":ck"):
        hints.append("Kit (ConvertKit)")
    if not hints:
        return "unknown — do not guess in your output"
    return " / ".join(dict.fromkeys(hints))  # dedupe, preserve order


def _should_humanize(report: Report) -> bool:
    """Skip the LLM call when nothing failed. Passing-only audits get a
    canned 'all clear' rendered elsewhere."""
    return any(not f.passed for f in report.findings)


def _failing_findings_payload(report: Report) -> str:
    """Serialize just the failing findings for the prompt — trims data we
    don't need for prose (raw bytes, sha256 etc. never appear in findings
    but being explicit keeps the prompt focused)."""
    import json

    failing = [
        {
            "check": f.check,
            "severity": f.severity.value,
            "message": f.message,
            "details": f.details,
        }
        for f in report.findings
        if not f.passed
    ]
    return json.dumps(failing, indent=2, default=str)


def humanize(
    report: Report,
    parsed: ParsedEmail,
    history_meta: dict | None = None,
) -> HumanizedReport | None:
    """Return a HumanizedReport, or None when the LLM was skipped or failed.

    Returns None:
      - when every finding passed (no failures to explain)
      - when OPENAI_API_KEY is not set
      - when the OpenAI call raised any exception

    Callers should treat None as 'render technical breakdown only.'
    """
    if not _should_humanize(report):
        return None

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        print("humanize: OPENAI_API_KEY not set; skipping summary.", file=sys.stderr)
        return None

    try:
        from openai import OpenAI
    except ImportError:
        print("humanize: openai package not importable; skipping summary.", file=sys.stderr)
        return None

    history_desc = "no baseline"
    if history_meta and history_meta.get("count"):
        history_desc = (
            f"{history_meta['count']} prior sends from "
            f"{history_meta.get('sender_domain') or 'this sender'} in the baseline"
        )

    body_text = (parsed.plain_text or "").strip()
    body_excerpt = body_text[:_BODY_EXCERPT_CHARS]
    if len(body_text) > _BODY_EXCERPT_CHARS:
        body_excerpt += "…"

    user_prompt = _USER_PROMPT_TEMPLATE.format(
        score=report.score,
        verdict=report.verdict,
        from_addr=report.from_addr or "(unknown)",
        subject=report.subject or "(no subject)",
        history_desc=history_desc,
        tool_hint=_infer_tool(parsed),
        excerpt_chars=_BODY_EXCERPT_CHARS,
        body_excerpt=body_excerpt or "(no plain-text body)",
        findings_json=_failing_findings_payload(report),
    )

    try:
        client = OpenAI(api_key=api_key)
        completion = client.beta.chat.completions.parse(
            model=_MODEL,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            response_format=HumanizedReport,
        )
        parsed = completion.choices[0].message.parsed
        return parsed
    except Exception as e:
        print(f"humanize: LLM call failed ({type(e).__name__}: {e}); skipping summary.",
              file=sys.stderr)
        return None
