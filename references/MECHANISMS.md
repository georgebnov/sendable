# Mechanisms

How the subtle checks actually decide, in plain English, with the regex and the
decision tree for each one. Read this when a finding surprises you and you want
to know what the check measured.

**Coverage.** This file explains the checks whose decision is not obvious from
its name: the content and authentication group, and scoring. It does not cover
all of them. [CHECKS.md](CHECKS.md) lists every check with its thresholds,
and says which ones have no entry yet.

**Code pointers.** Grep a check's id to find it. The id is the stable pointer:

```bash
grep -rn 'hidden_css_salting' engine/
```

The old `audit/` tree these sections were written against is gone. The decision
logic below was re-checked against `engine/`, but a diagram is a description, not
the code. The code wins.

---

## 0. How an audit runs end-to-end

```
  raw .eml bytes
        │
        ▼
  parse_eml(raw), stdlib email module, policy.default        engine/parse.py
        │
        │ produces ParsedEmail with:
        │   - headers          (dict, lowercase keys → list of values)
        │   - html             (text/html part, or None)
        │   - plain_text       (text/plain part, or None)
        │   - from_addr        (From header, raw string)
        │   - subject          (Subject header)
        │   - authentication_results  (list of Authentication-Results header values)
        ▼
  asyncio.gather, all 9 checks run concurrently               engine/runner.py
        │
        ├── auth.run               → list[Finding]
        ├── size.run               → list[Finding]
        ├── hidden_css.run         → list[Finding]
        ├── invisible_chars.run    → list[Finding]
        ├── homoglyph.run          → list[Finding]
        ├── unsubscribe.run        → list[Finding]
        ├── body_composition.run   → list[Finding]
        ├── link_quality.run       → list[Finding]
        └── observability.run      → list[Finding]
        │
        ▼
  flatten findings, compute score + verdict                    engine/severity.py
        │
        ▼
  Report (Pydantic)                                            engine/report.py
```

Each **Finding** carries:
- `check`: dotted identifier (e.g. `auth.dkim`, `content.homoglyphs`)
- `severity`: one of CRITICAL / HIGH / MEDIUM / LOW / INFO
- `passed`: boolean
- `message`: short human summary
- `details`: extra structured data (counts, hits, codepoints, etc.)

---

## 1. Parsing (the foundation every check depends on)


Simple flow:
1. Read raw bytes → Python's stdlib `email.message_from_bytes(..., policy=policy.default)`.
2. Collect headers into a dictionary, lowercasing keys. Each key maps to a list (some headers can appear multiple times: e.g. `Received`, `Authentication-Results`).
3. Walk MIME parts. First `text/html` part found → stored as `html`. First `text/plain` → stored as `plain_text`.
4. Pull `From`, `Subject`, `To` (all may exist), `Authentication-Results` (list).

What we deliberately **don't** do:
- **We never re-verify DKIM ourselves.** Re-verifying would fail on forwarded mail (body gets rewritten by forwarders, breaking the hash). Instead we read what the receiving mail server said in `Authentication-Results`.

---

## 2. Check: `auth.*`: authentication pass/fail


**What it looks at:** `email.authentication_results`: the list of `Authentication-Results` header values.

**The regex:**
```
\b(spf|dkim|dmarc|arc|bimi)\s*=\s*([a-zA-Z]+)
```

This finds `method=result` pairs. E.g. in `Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=...; dkim=pass header.d=...; dmarc=pass` it pulls out `spf → pass`, `dkim → pass`, `dmarc → pass`.

**Decision tree:**

```
authentication_results list is empty?
├── yes → HIGH / fail / "No Authentication-Results header; receiver did not authenticate
│         (or it was stripped)."
│         stop here, skip the rest
└── no  → join all AR values, run the regex, build {method: result} dict
          (first match wins if duplicates, setdefault)
          │
          ▼
          for each of (spf, dkim, dmarc):
            result = dict.get(method)   # may be None
            passed = (result == "pass")
            │
            ▼
            method is dmarc AND result in ("fail", "softfail")?
            ├── yes → CRITICAL / fail / "DMARC=fail"  (or softfail)
            ├── not passed (includes "missing") → HIGH / fail / "METHOD=<result or 'missing'>"
            └── passed → INFO / pass / "METHOD=pass"
          │
          ▼
          also emit INFO-level findings for arc / bimi if present
          (passed = (result == "pass"), informational only, no failure logic)
```

**Why DMARC fail is treated worse than SPF/DKIM fail:** DMARC is the only one whose explicit `fail` means "receiver policy says reject/quarantine this." SPF / DKIM failing alone doesn't mean the message bounced; DMARC failing tells us it very likely did or will.

---

## 3. Check: `size.html_bytes`: HTML body size


**What it looks at:** `email.html` (the text/html MIME part as a string).

**Thresholds:**
```
TARGET_BYTES     = 90,000   (we want under this)
GMAIL_CLIP_BYTES = 102,000  (Gmail truncates above this)
```

**Decision tree:**

```
email.html is None?
├── yes → MEDIUM / fail / "No text/html body found." (end)
└── no  → compute byte_len = len(email.html.encode("utf-8"))
          │
          ▼
          byte_len > 102,000?  (Gmail clip)
          ├── yes → CRITICAL / fail / "HTML is X bytes, exceeds Gmail clip limit." (end)
          └── no  → byte_len > 90,000?  (our target)
                    ├── yes → HIGH / fail / "HTML is X bytes, above target 90,000." (end)
                    └── no  → INFO / pass / "HTML is X bytes." (end)
```

**Why this check exists:** Gmail clips HTML above 102 KB, and crucially, it does so **silently**. Anything below the fold (unsubscribe link, important CTA) becomes invisible. The 90 KB target gives headroom. See §7 for a separate `render.unsub_clipped` check that specifically catches the worst consequence: unsubscribe links falling below the clip.

---

## 4. Check: `content.hidden_css_salting`: hidden-text detection


### 4.1 Hidden-style pattern list

These regexes each identify one way CSS can hide visible content. They run against both inline `style="..."` attributes **and** selectors inside `<style>` blocks.

| Regex | Meaning |
| --- | --- |
| `display\s*:\s*none` | element removed from layout |
| `visibility\s*:\s*hidden` | invisible but takes up space |
| `opacity\s*:\s*0(?:\.0+)?\b` | fully transparent |
| `font-size\s*:\s*0(?:px\|pt\|em\|rem)?\b` | zero-height text |
| `mso-hide\s*:\s*all` | Outlook-specific hiding |
| `text-indent\s*:\s*-\d{3,}px` | offscreen via negative indent |
| `left\s*:\s*-\d{3,}px` | offscreen via absolute positioning |
| `top\s*:\s*-\d{3,}px` | offscreen via absolute positioning |

All patterns use `re.IGNORECASE`.

### 4.2 Classifying whether the hidden text is adversarial

Once we've found hidden text, we classify it as either `adversarial` or `benign` via `_classify_hidden(text)`:

**Instruction-verb regex** (triggers "adversarial"):
```
\b(ignore|disregard|forget|override|previous|instructions?|assistant|admin|
   system\s+prompt|you\s+are|act\s+as)\b
```

**Noise-character regex** (stripped before measuring "real" content length):
```
[\s­͏​-‏ -  ⁠⁤⁦-⁯﻿]
```

**Decision:**
```
text contains any instruction-verb?       → adversarial
stripped-noise length > 300 chars?        → adversarial   (too much hidden content)
otherwise                                 → benign        (short preheader-ish text)
```

### 4.3 Two paths: inline `style="..."` and `<style>` blocks

Both paths live in `run(email)`; we parse the HTML once with BeautifulSoup then walk through both surfaces.

**Path A: inline style attributes:**
```
for each element in the HTML that has a `style` attribute:
    matched_patterns = patterns that match the style string
    if no matches: continue
    element_text = the element's own visible text
    strip noise chars (ZWSP, soft hyphens, etc.) from element_text
    ├── result is empty → skip  (spacer <td>, tracking <img>, empty hide-wrapper;
    │                             not hiding any real content)
    └── has content → classify, record hit
    record a hit: { pattern, tag, where: "style_attr", class: classification }
```

**Design choice: content-touching or not is the axis that matters.** Any hidden-CSS that's actually hiding content-bearing text stays HIGH or worse: even if the content looks innocuous, we can't reliably distinguish "benign" from "adversarial pattern we haven't seen yet." Elements with no text aren't hiding content; they're scaffolding.

**Path B: `<style>` blocks (rewritten 2026-04-21):**
```
for each <style> tag in the HTML:
    css = the tag's text content
    flatten @media / @supports / @keyframes wrappers
      (by stripping the `@media (...) {` opener so inner rules parse at top level)
    │
    ▼
    for each CSS rule found by the regex  ([^{}]+ { [^{}]* }):
        selector = text before the {
        body     = text inside { }
        skip if selector is empty or starts with @
        │
        ▼
        do any hidden-style patterns match the body?
        ├── no → skip this rule
        └── yes → resolve the selector against the HTML with soup.select(selector)
                  (supports multiple comma-separated selectors)
                  │
                  ▼
                  found matching elements?
                  ├── no  → dead CSS / @keyframes noise / structural-only → skip
                  └── yes → concatenate their text
                            classification = _classify_hidden(concatenated_text)
                            record a hit: { pattern, where: "style_block",
                                            selector, class: classification }
```

**The old blanket rule (now removed):** previously, *any* `<style>` block containing any hidden-style pattern was marked CRITICAL regardless of whether the rule even targeted real content. That false-positived on every HubSpot/Mailchimp/Klaviyo template.

### 4.4 Final severity for this check

```
collect all hits from Path A and Path B
│
▼
any hit classified "adversarial"?
├── yes → CRITICAL / fail / "Hidden-text patterns detected (N hit(s); adversarial=True)."
├── at least one hit but none adversarial → HIGH / fail / "...adversarial=False."
└── zero hits → INFO / pass / "No hidden-text salting patterns detected."
```

**Rationale for keeping HIGH on benign content-touching hits:** we deliberately don't downgrade "short hidden text with no instruction verbs" to LOW. You can't reliably tell "benign" from "adversarial pattern I haven't added to my lexicon yet." Any hidden-CSS that touches real content forces the user to look at their template, which is the correct behavior, since legitimate email rarely needs to hide visible text. The gold-standard HubSpot fixture now scores 100 because its only hidden-CSS elements (a spacer `<td>`, a tracking `<img>`) are non-content-touching and skipped entirely by Path A.

---

## 5. Check: `content.bidi_override` + `content.zero_width`: invisible characters


This file runs **two** checks in one module, returning one Finding for each.

### 5.1 What counts as "visible text"

Before running the character scans, we build a string of what the reader would actually see:

```
visible_text =
    subject line
  + HTML body with hidden-CSS elements removed
     (we decompose anything with display:none / visibility:hidden / opacity:0
      inline styles, those belong to the hidden_css check, not this one)
  + text/plain body
```

This avoids double-counting: if a hidden div has a zero-width char, the `hidden_css` check owns it; the invisible-chars check should only see what the user sees.

The hidden-style regex used here (simpler than `hidden_css` since it only runs on inline styles to prune elements):
```
display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?\b
```

### 5.2 Bidirectional override characters (`content.bidi_override`)

**Regex:** `[‭‮]`. U+202D (LEFT-TO-RIGHT OVERRIDE) and U+202E (RIGHT-TO-LEFT OVERRIDE).

**Decision:**
```
any bidi chars in visible_text?
├── yes → CRITICAL / fail / "Bidirectional override characters detected (N).
│         Prompt-injection / spoofing risk."
│         details: { count, list of unique codepoints in hex }
└── no  → INFO / pass / "No bidirectional override characters."
```

**Why CRITICAL:** these codepoints flip display order mid-string and are the canonical pattern in the Apple Intelligence prompt-injection research. Legit email doesn't use them.

### 5.3 Zero-width / other invisible characters (`content.zero_width`)

**Regex:**
```
[​-‏ -‬  ⁠⁤⁦-⁯﻿]
```

Covers: zero-width spaces, zero-width non-joiners, zero-width joiners, LTR/RTL marks, line/paragraph separators, narrow no-break space, medium mathematical space, word joiner, various invisible plus/times chars, the full LRI/RLI/PDI embedding block, and BOM (U+FEFF).

**Deliberately excluded:** U+00AD (SOFT HYPHEN): legitimate hyphenation hint used by email clients; including it would false-positive everywhere.

**Decision:**
```
any zero-width chars in visible_text?
├── yes → HIGH / fail / "Zero-width / invisible characters detected (N)."
│         details: { count, list of unique codepoints in hex }
└── no  → INFO / pass / "No zero-width / invisible characters."
```

**Why HIGH rather than CRITICAL:** zero-width chars are sometimes used legitimately for script shaping (e.g., complex Indic scripts). High signal but not a definitive attack marker the way bidi overrides are.

---

## 6. Check: `content.homoglyphs`: visually-confusable characters


Uses the `confusable_homoglyphs` library, which wraps Unicode's official confusable-character data.

### 6.1 What gets scanned

```
samples = []
if subject:                           samples.append(("subject", subject))
if html:
    body_text = all visible text from HTML, whitespace-joined
    samples.append(("body", body_text))
    for every <a href="..."> in HTML: samples.append(("link_href", href))
```

Hrefs get scanned individually because a homoglyph in a link is dramatically worse than one in body text (classic phishing: `pаypal.com` where the `а` is Cyrillic).

### 6.2 How detection works

```
for each (where, text) pair:
    result = confusables.is_confusable(text, preferred_aliases=["latin"])
    │
    ▼
    result is False (clean)?
    ├── yes → skip
    └── no  → result is a list of dicts, each with {character, alias, ...}
              for each entry:
                if alias in ("LATIN", "COMMON"): skip   (not actually confusable)
                else: record { where, char, alias }
```

The `preferred_aliases=["latin"]` parameter tells the library "we expect Latin script; flag anything from Cyrillic/Greek/etc. that resembles a Latin char."

**Known limitation:** `preferred_aliases=["latin"]` is hardcoded. A Russian-language newsletter from a Cyrillic domain would false-positive every Cyrillic letter. The deferred fix adds language detection and picks the alias dynamically.

### 6.3 Severity

```
no hits?
├── INFO / pass / "No homoglyphs detected."
any hit where `where == "link_href"`?
├── CRITICAL / fail / "Homoglyph characters detected (N)."  (phishing vector)
otherwise (hits only in subject or body):
└── HIGH / fail / "Homoglyph characters detected (N)."
```

Details field includes the first 20 hits with their `where`, `char`, and `alias`.

---

## 7. Check: `content.list_unsubscribe_*` + body unsub + clip-risk


Gmail (Feb 2024), Yahoo (Feb 2024), and Microsoft (May 2025) now bulk-reject mail without RFC 8058 one-click unsubscribe. For a bulk sender this is effectively a delivery blocker.

### 7.1 "Is this bulk mail?" heuristic

Severity for missing unsubscribe headers depends on whether the message looks like bulk mail. A personal 1:1 email shouldn't need List-Unsubscribe, so we degrade severity to INFO in that case.

**Bulk signals** (presence of any one → treat as bulk):
- `List-ID` header present
- `Feedback-ID` header present
- Any of: `X-Mailchimp-Campaign-ID`, `X-Campaign`, `X-Campaign-ID`, `X-Klaviyo-MessageID`, `X-AC-Campaign-ID`
- `Precedence: bulk` header

### 7.2 `content.list_unsubscribe_header`

**Decision:**
```
List-Unsubscribe header present?
├── yes → INFO / pass / "List-Unsubscribe header present."
└── no  → is the email bulk?
          ├── yes → CRITICAL / fail / "Missing List-Unsubscribe on bulk mail.
          │         Gmail/Yahoo/Microsoft bulk-reject without it."
          └── no  → INFO / fail  (no impact on score, non-bulk doesn't need this)
```

### 7.3 `content.list_unsubscribe_post`

**Regex for the required token** (RFC 8058):
```
List-Unsubscribe\s*=\s*One-Click
```

**Decision:**
```
List-Unsubscribe-Post header matches regex?
├── yes → INFO / pass / "List-Unsubscribe-Post: List-Unsubscribe=One-Click present (RFC 8058)."
└── no  → bulk? CRITICAL / fail, else INFO / fail
```

### 7.4 `content.unsubscribe_link_body`

Both Gmail and Yahoo sender guidelines also require a visible unsubscribe link in the body.

**Match criterion** (OR: generous):
- Anchor text contains `unsubscribe` / `opt out` / `opt-out` / `email preferences` (case-insensitive)
- **OR** `href` contains any of: `unsubscribe` / `optout` / `opt-out` / `email-preferences` / `email-settings` / `remove-me`

**Decision:**
```
any <a> element satisfies the match?
├── yes → INFO / pass / "Visible unsubscribe link present in body."
└── no  → MEDIUM / fail / "No visible unsubscribe link found in HTML body."
```

### 7.5 `render.unsub_clipped` (fires only when bad)

Gmail clips HTML bodies above ~102 KB silently. If the visible unsubscribe link sits past that offset, users can't find it → they click Report Spam instead → sender reputation tanks.

**Decision:**
```
HTML size ≤ 102 KB?  → no finding emitted (not at risk)
HTML > 102 KB:
    find byte-offset of the visible unsubscribe anchor in the HTML string
    │
    ▼
    offset > 102,000?
    ├── yes → CRITICAL / fail / "Unsubscribe link at byte offset X is past
    │         Gmail's clip threshold; users won't see it."
    └── no  → no finding emitted (visible before the clip, already covered
              by size.html_bytes)
```

---

## 8. Check: `content.plain_text_alternative` + `content.image_text_ratio`


### 8.1 `content.plain_text_alternative`

A non-empty `text/plain` MIME alternative is itself a filter-legitimacy signal.

**Threshold:** `_PLAIN_MIN_CHARS = 100`

**Decision:**
```
len(plain_text.strip()) >= 100?
├── yes → INFO / pass / "text/plain alternative present (N chars)."
└── no  → MEDIUM / fail / "text/plain alternative missing or too short (N chars).
          A non-empty plain-text part is a filter-legitimacy signal."
```

### 8.2 `content.image_text_ratio`

Image-heavy emails with thin text trip multiple spam filters (Email on Acid empirical: under 500 chars visible text plus more than 3 images).

**Thresholds:**
```
_VISIBLE_TEXT_FLOOR   = 500   (characters of visible body text)
_IMAGE_COUNT_CEILING  = 3     (number of <img> tags)
```

**Decision:**
```
strip <script> and <style> from HTML, then extract get_text(strip=True)
whitespace-normalize and count chars → visible_len
count <img> tags → image_count
│
▼
visible_len < 500 AND image_count > 3?
├── yes → HIGH / fail / "Image-heavy layout: N images with only M chars
│         of visible text. Trips multiple spam filters."
└── no  → INFO / pass / "Visible text N chars, M images."
```

---

## 9. Check: `content.url_shortener` + `content.anchor_href_mismatch`


### 9.1 `content.url_shortener`

Shortener hostnames obscure destination reputation and compound with other SpamAssassin rules.

**Hostname list** (exact registrable-domain match):
```
bit.ly, t.co, tinyurl.com, goo.gl, ow.ly, is.gd, buff.ly, bitly.com,
rb.gy, cutt.ly, shorturl.at, rebrand.ly, trib.al, tiny.cc, soo.gd,
s.id, lnkd.in
```

**Decision:**
```
for each <a href="..."> in HTML:
    parse href with urlparse; skip if scheme not http/https
    extract hostname, compute registrable-domain (eTLD+1)
    if registrable-domain is in the shortener set → record hit
│
▼
any hits?
├── yes → MEDIUM / fail / "N link(s) use URL shortener domains (e.g. bit.ly)."
└── no  → INFO / pass / "No URL-shortener domains detected in links."
```

### 9.2 `content.anchor_href_mismatch`

Classic phishing pattern: visible text says "paypal.com" but href goes to a different domain.

**Extract apparent domain from visible text** (regex):
```
\b([a-z0-9][a-z0-9\-]{0,62}(?:\.[a-z0-9][a-z0-9\-]{0,62})+\.[a-z]{2,})\b
```
(with a short ignore-list for `e.g.`, `i.e.`, `etc.`, etc. that happen to match the shape)

**Registrable-domain comparison** (stdlib approximation, no `tldextract` dep):
- Normal single-label TLD: last two labels (`foo.bar.example.com` → `example.com`)
- Known multi-label TLD (e.g. `.co.uk`, `.com.au`, `.co.jp`): last three labels. Explicit known-list of ~20 TLDs covers the cases PoC traffic typically hits.

**Decision:**
```
for each <a href="..."> with parseable http/https href AND visible text
containing a domain-shape match:
    text_reg = registrable(extracted_text_domain)
    href_reg = registrable(href_host)
    if both non-empty AND text_reg != href_reg → record mismatch
│
▼
any hits?
├── yes → HIGH / fail / "N link(s) show one domain in visible text but
│         link to another (classic phishing pattern)."
└── no  → INFO / pass / "No anchor-text / href domain mismatches detected."
```

**Known limitation:** the stdlib registrable-domain approximation covers ~90% of cases. An upgrade to `tldextract` would give perfect eTLD+1 parsing using the Public Suffix List.

---

## 10. Check: `headers.feedback_id`: observability only


Gmail doesn't send ARF complaint reports for privacy reasons. Bulk senders rely on `Feedback-ID` to attribute complaints via Gmail Postmaster Tools. Missing the header on bulk mail means reputation regressions are silent.

**Decision:**
```
Feedback-ID header present?
├── yes → INFO / pass / "Feedback-ID present (Postmaster Tools visibility)."
└── no  → is this bulk mail? (same heuristic as §7.1)
          ├── yes → INFO / fail / "Bulk mail without Feedback-ID header..."
          └── no  → no finding emitted (1:1 mail doesn't need it)
```

Severity is capped at INFO deliberately: this is observability, not delivery. The missing header doesn't block mail; it blocks your ability to see *why* mail is getting blocked.

---

## 11. Scoring + verdict (how findings become a 0-100 number)


### 11.1 Severity levels

```
CRITICAL  HIGH  MEDIUM  LOW  INFO
```

### 11.2 Score formula

```
has_critical = any firing Finding has severity CRITICAL

if has_critical:
    score starts at SCORE_CRITICAL_CAP = 40
else:
    score starts at 100

for each firing Finding (passed=False):
    skip if severity is CRITICAL  (cap already applied)
    deduct by severity:
        HIGH   = -15
        MEDIUM = -5
        LOW    = -2
        INFO   = -0   (info-level failures are informational only)

floor at 0.
```

### 11.3 Verdict thresholds

```
SCORE_GO_MIN     = 85
SCORE_REVIEW_MIN = 65

if has_critical:           → NO_GO
elif score >= 85:          → GO
elif score >= 65:          → REVIEW
else:                      → NO_GO
```

### 11.4 Concrete worked example (the gold-standard HubSpot fixture)

Firing findings: **none**.

No CRITICAL → score starts at 100.
No deductions → **100**.

100 ≥ SCORE_GO_MIN → **GO**.

(Before the 2026-04-21 fixes: `<style>`-block CSS-awareness + inline content-touching skip: this fixture scored 40/NO_GO then 85/GO; it's now at the logical ceiling.)

### 11.5 Concrete worked example (the adversarial fixture)

Firing findings:
- `content.hidden_css_salting`: CRITICAL (prompt-injection instruction verbs in hidden div)
- `content.homoglyphs`: CRITICAL (Cyrillic lookalike in link_href)
- `content.zero_width`: HIGH (U+200B in body)
- `content.list_unsubscribe_header`: INFO (missing, but not bulk: no score impact)
- `content.list_unsubscribe_post`: INFO (same)

has_critical = True → score starts at 40.
Skip CRITICAL deductions. HIGH deduction → 40 − 15 = **25**.

has_critical → **NO_GO** (verdict overrides score band).

---

## 12. Summary table

There was a table here listing 19 checks with their source filenames. It named
the `auth.py`-style paths from the `audit/` tree, which is gone, and it covered
19 of the checks the audit emits.

[CHECKS.md](CHECKS.md) is the complete list, with thresholds and severity for
each one. One list, not two.

## 13. What the audit still does not do

Checked against `engine/` when this file moved into `references/`. Everything
below was verified absent, not assumed.

- **Spamhaus DBL / SURBL / URIBL / Safe Browsing**: no DNS lookups on URL hostnames yet. Consultant flagged this as next-up (requires `dnspython`, network latency, rate-limit handling).
- **`tldextract` upgrade for eTLD+1 parsing**: current stdlib approximation in `link_quality` is ~90% accurate on common TLDs. Rare multi-label public suffixes may misclassify.
- **Live RFC 8058 unsubscribe POST**: we check headers/body for unsubscribe presence but don't POST the URL to verify it returns 200 without auth.
- **From-header sanity**: display-name vs address comparison with `parseaddr`. Classic phishing catch (display "PayPal Security", actual address random).
- **SpamAssassin integration**: not wired.
- **Message-ID / Date / Reply-To sanity**: no format / temporal / MX-resolution checks.
- **Subject heuristics**: no ALL-CAPS or excessive-punctuation detection.
- **Language-aware homoglyph aliases**: `preferred_aliases=["latin"]` hardcoded; will false-positive on non-English newsletters.
- **Alt-text coverage on `<img>`**: not checked; accessibility-adjacent quality signal.
- **Apple Intelligence preheader pre-empt** (iOS 18+): front-load value in first ~100 body chars. Not checked.
- **iOS Link Tracking Protection**: warn when tracking params exist that will get stripped.
- **Non-ASCII byte-bloat**. UTF-8 multi-bytes push HTML toward the clip limit faster than `len()` suggests.

Four items that used to sit in this list now ship, and saying otherwise sent an
agent to tell a user the opposite of what the README says: the DBL and SURBL
scans, the live RFC 8058 unsubscribe probe (`content.list_unsub_live_probe`),
Date and Message-ID and Reply-To sanity (`headers.date_sanity`,
`headers.message_id`, `auth.reply_to_alignment`), and subject heuristics
including ALL-CAPS and punctuation (`copywriting.subject_heuristics`,
`copywriting.body_shouting`).
