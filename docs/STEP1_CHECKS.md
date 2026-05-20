# Step 1 — Audit Checks: Plain-English Reference

*Everything the tool looks at, in plain English, with the exact regex and decision tree for each check. Intended for consultant review. Code references are point-in-time (2026-04-21); see `audit/` for current implementation.*

---

## 0. How an audit runs end-to-end

```
  raw .eml bytes
        │
        ▼
  parse_eml(raw) — stdlib email module, policy.default        audit/parse.py
        │
        │ produces ParsedEmail with:
        │   - headers          (dict, lowercase keys → list of values)
        │   - html             (text/html part, or None)
        │   - plain_text       (text/plain part, or None)
        │   - from_addr        (From header, raw string)
        │   - subject          (Subject header)
        │   - authentication_results  (list of Authentication-Results header values)
        ▼
  asyncio.gather — all 9 checks run concurrently               audit/runner.py
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
  flatten findings, compute score + verdict                    audit/severity.py
        │
        ▼
  Report (Pydantic)                                            audit/report.py
```

Each **Finding** carries:
- `check`  — dotted identifier (e.g. `auth.dkim`, `content.homoglyphs`)
- `severity` — one of CRITICAL / HIGH / MEDIUM / LOW / INFO
- `passed` — boolean
- `message` — short human summary
- `details` — extra structured data (counts, hits, codepoints, etc.)

---

## 1. Parsing (the foundation every check depends on)

File: `audit/parse.py`

Simple flow:
1. Read raw bytes → Python's stdlib `email.message_from_bytes(..., policy=policy.default)`.
2. Collect headers into a dictionary, lowercasing keys. Each key maps to a list (some headers can appear multiple times — e.g. `Received`, `Authentication-Results`).
3. Walk MIME parts. First `text/html` part found → stored as `html`. First `text/plain` → stored as `plain_text`.
4. Pull `From`, `Subject`, `To` (all may exist), `Authentication-Results` (list).

What we deliberately **don't** do:
- **We never re-verify DKIM ourselves.** Re-verifying would fail on forwarded mail (body gets rewritten by forwarders, breaking the hash). Instead we read what the receiving mail server said in `Authentication-Results`.

---

## 2. Check: `auth.*` — authentication pass/fail

File: `audit/checks/auth.py`

**What it looks at:** `email.authentication_results` — the list of `Authentication-Results` header values.

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
          (first match wins if duplicates — setdefault)
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
          (passed = (result == "pass"), informational only — no failure logic)
```

**Why DMARC fail is treated worse than SPF/DKIM fail:** DMARC is the only one whose explicit `fail` means "receiver policy says reject/quarantine this." SPF / DKIM failing alone doesn't mean the message bounced; DMARC failing tells us it very likely did or will.

---

## 3. Check: `size.html_bytes` — HTML body size

File: `audit/checks/size.py`

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

## 4. Check: `content.hidden_css_salting` — hidden-text detection

File: `audit/checks/hidden_css.py`. The most complex check. Rewritten 2026-04-21 to be CSS-aware rather than blanket-flagging.

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

**Path A — inline style attributes:**
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

**Design choice: content-touching or not is the axis that matters.** Any hidden-CSS that's actually hiding content-bearing text stays HIGH or worse — even if the content looks innocuous, we can't reliably distinguish "benign" from "adversarial pattern we haven't seen yet." Elements with no text aren't hiding content; they're scaffolding.

**Path B — `<style>` blocks (rewritten 2026-04-21):**
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

**Rationale for keeping HIGH on benign content-touching hits:** we deliberately don't downgrade "short hidden text with no instruction verbs" to LOW. You can't reliably tell "benign" from "adversarial pattern I haven't added to my lexicon yet." Any hidden-CSS that touches real content forces the user to look at their template — which is the correct behavior, since legitimate email rarely needs to hide visible text. The gold-standard HubSpot fixture now scores 100 because its only hidden-CSS elements (a spacer `<td>`, a tracking `<img>`) are non-content-touching and skipped entirely by Path A.

---

## 5. Check: `content.bidi_override` + `content.zero_width` — invisible characters

File: `audit/checks/invisible_chars.py`

This file runs **two** checks in one module, returning one Finding for each.

### 5.1 What counts as "visible text"

Before running the character scans, we build a string of what the reader would actually see:

```
visible_text =
    subject line
  + HTML body with hidden-CSS elements removed
     (we decompose anything with display:none / visibility:hidden / opacity:0
      inline styles — those belong to the hidden_css check, not this one)
  + text/plain body
```

This avoids double-counting: if a hidden div has a zero-width char, the `hidden_css` check owns it; the invisible-chars check should only see what the user sees.

The hidden-style regex used here (simpler than `hidden_css` since it only runs on inline styles to prune elements):
```
display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?\b
```

### 5.2 Bidirectional override characters (`content.bidi_override`)

**Regex:** `[‭‮]` — U+202D (LEFT-TO-RIGHT OVERRIDE) and U+202E (RIGHT-TO-LEFT OVERRIDE).

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

**Deliberately excluded:** U+00AD (SOFT HYPHEN) — legitimate hyphenation hint used by email clients; including it would false-positive everywhere.

**Decision:**
```
any zero-width chars in visible_text?
├── yes → HIGH / fail / "Zero-width / invisible characters detected (N)."
│         details: { count, list of unique codepoints in hex }
└── no  → INFO / pass / "No zero-width / invisible characters."
```

**Why HIGH rather than CRITICAL:** zero-width chars are sometimes used legitimately for script shaping (e.g., complex Indic scripts). High signal but not a definitive attack marker the way bidi overrides are.

---

## 6. Check: `content.homoglyphs` — visually-confusable characters

File: `audit/checks/homoglyph.py`

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

**Known limitation (tracked in BACKLOG):** `preferred_aliases=["latin"]` is hardcoded. A Russian-language newsletter from a Cyrillic domain would false-positive every Cyrillic letter. The deferred fix adds language detection and picks the alias dynamically.

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

File: `audit/checks/unsubscribe.py`. Emits up to 4 findings.

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
          └── no  → INFO / fail  (no impact on score — non-bulk doesn't need this)
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

**Match criterion** (OR — generous):
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
    └── no  → no finding emitted (visible before the clip — already covered
              by size.html_bytes)
```

---

## 8. Check: `content.plain_text_alternative` + `content.image_text_ratio`

File: `audit/checks/body_composition.py`

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

File: `audit/checks/link_quality.py`

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

**Known limitation (tracked in BACKLOG):** the stdlib registrable-domain approximation covers ~90% of cases. An upgrade to `tldextract` would give perfect eTLD+1 parsing using the Public Suffix List.

---

## 10. Check: `headers.feedback_id` — observability only

File: `audit/checks/observability.py`

Gmail doesn't send ARF complaint reports for privacy reasons. Bulk senders rely on `Feedback-ID` to attribute complaints via Gmail Postmaster Tools. Missing the header on bulk mail means reputation regressions are silent.

**Decision:**
```
Feedback-ID header present?
├── yes → INFO / pass / "Feedback-ID present (Postmaster Tools visibility)."
└── no  → is this bulk mail? (same heuristic as §7.1)
          ├── yes → INFO / fail / "Bulk mail without Feedback-ID header..."
          └── no  → no finding emitted (1:1 mail doesn't need it)
```

Severity is capped at INFO deliberately — this is observability, not delivery. The missing header doesn't block mail; it blocks your ability to see *why* mail is getting blocked.

---

## 11. Scoring + verdict (how findings become a 0-100 number)

File: `audit/severity.py`

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

(Before the 2026-04-21 fixes — `<style>`-block CSS-awareness + inline content-touching skip — this fixture scored 40/NO_GO then 85/GO; it's now at the logical ceiling.)

### 11.5 Concrete worked example (the adversarial fixture)

Firing findings:
- `content.hidden_css_salting`: CRITICAL (prompt-injection instruction verbs in hidden div)
- `content.homoglyphs`: CRITICAL (Cyrillic lookalike in link_href)
- `content.zero_width`: HIGH (U+200B in body)
- `content.list_unsubscribe_header`: INFO (missing, but not bulk — no score impact)
- `content.list_unsubscribe_post`: INFO (same)

has_critical = True → score starts at 40.
Skip CRITICAL deductions. HIGH deduction → 40 − 15 = **25**.

has_critical → **NO_GO** (verdict overrides score band).

---

## 12. Summary table — all checks at a glance

| Check | File | What it reads | Worst severity | Regex-heavy? |
| --- | --- | --- | --- | --- |
| `auth.authentication_results` | auth.py | `email.authentication_results` presence | HIGH (missing) | No |
| `auth.spf` | auth.py | `spf=...` in AR | HIGH (fail/missing) | `\b(spf|dkim|dmarc|arc|bimi)\s*=\s*([a-zA-Z]+)` |
| `auth.dkim` | auth.py | `dkim=...` in AR | HIGH (fail/missing) | same |
| `auth.dmarc` | auth.py | `dmarc=...` in AR | **CRITICAL** on fail/softfail | same |
| `auth.arc` / `auth.bimi` | auth.py | informational | INFO only | same |
| `size.html_bytes` | size.py | `len(html.encode('utf-8'))` | **CRITICAL** over 102 KB | none |
| `content.hidden_css_salting` | hidden_css.py | inline styles + `<style>` rules + element text | **CRITICAL** if adversarial content | 8 hidden patterns + instruction-verb regex |
| `content.bidi_override` | invisible_chars.py | subject + visible body | **CRITICAL** | `[‭‮]` |
| `content.zero_width` | invisible_chars.py | subject + visible body | HIGH | `[​-‏ -‬  ⁠⁤⁦-⁯﻿]` |
| `content.homoglyphs` | homoglyph.py | subject + body text + all `<a href>` | **CRITICAL** if in link_href, else HIGH | uses `confusable_homoglyphs` library |
| `content.list_unsubscribe_header` | unsubscribe.py | `List-Unsubscribe` header + bulk heuristic | **CRITICAL** (bulk, missing) / INFO (non-bulk) | none |
| `content.list_unsubscribe_post` | unsubscribe.py | `List-Unsubscribe-Post` + bulk heuristic | **CRITICAL** (bulk, missing) / INFO (non-bulk) | `List-Unsubscribe\s*=\s*One-Click` |
| `content.unsubscribe_link_body` | unsubscribe.py | HTML `<a>` elements: visible text + href | MEDIUM (missing) | 2 text/href patterns |
| `render.unsub_clipped` | unsubscribe.py | HTML byte-offset of unsub anchor vs 102 KB | **CRITICAL** (only fires when bad) | none |
| `content.plain_text_alternative` | body_composition.py | `email.plain_text` length | MEDIUM (missing / <100 chars) | none |
| `content.image_text_ratio` | body_composition.py | visible-text char count + `<img>` count | HIGH (text<500 AND imgs>3) | none |
| `content.url_shortener` | link_quality.py | registrable-domain of each `<a href>` | MEDIUM (any shortener hit) | 17 known shorteners |
| `content.anchor_href_mismatch` | link_quality.py | visible text domain vs href registrable-domain | HIGH (any mismatch hit) | domain-extract regex |
| `headers.feedback_id` | observability.py | `Feedback-ID` header + bulk heuristic | INFO only | none |

---

## 13. Drift checks (Step 3, Phase 1) — cross-email analysis

The audit flow can optionally receive a sender's `history` (from `memory/store.history_for(sender_domain, ...)`). When provided, six additional drift checks run in `audit/drift/runner.py:run_drift()` after the single-email checks and merge their findings into the same Report.

**Cold-start gating** (`cold_start_ok`): row count only — `min_rows=3` default. The rotation/churn check (D10) overrides with `min_rows=8` because estimating churn-ratio needs a bigger sample. When the gate doesn't pass, a check returns `INFO: insufficient history for drift analysis` and no false alarms fire.

(An earlier version of this gate also required `min_age_days=14`, but age was being measured against `received_at` — the ingest timestamp — not the email's actual send date. For bootstrapped historical rows all ingested today, that gate falsely tripped even on years of real history. Row count is the actual useful signal; per-check logic provides the rest of the sufficiency test.)

**Sender-cadence rule of thumb:** drift starts firing on the 3rd send from a given sender (for auth / unsub / Reply-To checks) or the 8th send (for display-name rotation). Bootstrap-ingesting old history engages drift immediately.

**Shared derived columns** (populated at save time by `memory/derived.py:extract_all`): `from_domain`, `from_local`, `display_name`, `reply_to_domain`, `num_images`, `spf_result`, `dkim_result`, `dmarc_result`, `dmarc_policy`, `list_unsub_has_mailto`, `list_unsub_has_https`, `list_unsub_has_oneclick_post`. These are computed once and re-read by every drift check from SQLite.

### 13.1 `drift.d01_dmarc_regression` — DMARC fail on a historically-passing sender

**Decision tree:**
```
if cold_start → INFO: insufficient history
if current dmarc_result not in {fail, softfail} → INFO pass
count DMARC results in last 10 rows (non-null only)
if ≥10 are all pass AND current is fail/softfail → CRITICAL
else → HIGH
```

### 13.2 `drift.d03_auth_flip` — SPF / DKIM pass-to-fail

```
compute pass-rate of SPF and DKIM in last 10 rows
if SPF pass-rate ≥0.9 AND current SPF in {fail, softfail}: mark spf_flipped
if DKIM pass-rate ≥0.9 AND current DKIM in {fail, neutral}: mark dkim_flipped
both flipped → CRITICAL
exactly one flipped → HIGH
neither → INFO pass
```

### 13.3 `drift.d04_dmarc_policy_downgrade` — policy rank regression

Policies rank `none=0 < quarantine=1 < reject=2`, parsed from the `(p=...)` comment in the `dmarc=...` Authentication-Results segment.

```
if no p= comment in current AR → INFO (cannot evaluate)
find max rank observed in last 30 days of history (requires non-null dmarc_policy)
if current rank < historical max → HIGH / "policy downgraded"
else → INFO pass
```

(Upgrades are silent in Phase 1; positive-drift handling arrives in Phase 3.)

### 13.4 `drift.d08_list_unsub_regression` — RFC 8058 compliance loss

```
compute present_rate = fraction of last 10 with any List-Unsubscribe header
if present_rate ≥0.8 AND current has neither mailto nor https → HIGH / "header absent"
compute oneclick_rate = fraction of last 10 with list_unsub_has_oneclick_post=1
if oneclick_rate ≥0.8 AND current != 1 (None or 0) → HIGH / "one-click lost"
compute https_rate = fraction of last 10 with list_unsub_has_https=1
if https_rate ≥0.8 AND current https != 1 AND current mailto == 1 → MEDIUM / "downgraded to mailto-only"
else → INFO pass
```

### 13.5 `drift.d10_display_name_rotation` — identity drift + friendly-from spoof

Two concerns in one check:

**(a) Friendly-from spoof (fires without history):**
```
display name contains `@`:
    extract the domain after the `@`
    if that domain ≠ from_domain AND neither is a substring of the other → HIGH
    (this prevents false positives on Kit/ConvertKit's `"info@brand.com" <info@brand.com>` pattern)
display name contains a TLD-like token but no `@`:
    if from_domain is NOT a substring of the display name → HIGH
display name contains a known brand token ({paypal, google, microsoft, apple, amazon, ...})
    but from_domain does NOT contain that brand → HIGH
```

**(b) Rotation over last 90 days (requires ≥8 history rows):**
```
collect set S of distinct display_names in last 90 days
n_rows = size of window; churn_ratio = |S| / n_rows
if current name ∉ S AND |S| ≥ 3 → MEDIUM / "new name"
if churn_ratio > 0.5 → HIGH / "excessive rotation"
elif churn_ratio > 0.3 → MEDIUM / "elevated rotation"
```

Both (a) and (b) can fire on the same message — details captured separately.

### 13.6 `drift.d11_reply_to_divergence` — Reply-To drift, bulk only

Reuses the `_is_bulk(email)` heuristic from `audit/checks/unsubscribe.py`. Non-bulk mail is silent — personal 1:1 email legitimately uses many different Reply-To values.

```
if not bulk → INFO
if cold_start → INFO: insufficient history
if current reply_to_domain is null or matches from_domain → INFO pass

prior_rows = history rows that had a reply_to_domain set
if |prior_rows| < 3 → INFO: sparse (not enough sample)
prior = set of distinct reply_to_domain values across those rows

if current reply_to_domain in prior → INFO pass
is_new_freemail = current reply_to_domain ∈ {gmail.com, outlook.com, yahoo.com, proton.me, icloud.com, yandex.*, mail.ru, aol.com, ...}
had_freemail_prior = any prior is freemail
if is_new_freemail AND NOT had_freemail_prior → CRITICAL
else → HIGH
```

### 13.7 How drift integrates with scoring

Drift findings carry severity the same way audit findings do — a drift CRITICAL caps the score at 40 just like an audit CRITICAL, a drift HIGH deducts 15, etc. The verdict thresholds (§11.3) don't change. A sender whose email produces `drift.d01_dmarc_regression CRITICAL` will always land at NO_GO regardless of its otherwise-clean audit findings, which is correct — DMARC regression on bulk mail is a real delivery-blocking event.

### 13.8 What Step 3 Phase 1 does NOT cover yet

- **Phase 2 checks** (D02 DKIM `d=` shift, D05 Received IP escape, D06 ESP fingerprint tuple, D07 Return-Path shift, D09 new-link-destination Jaccard, D12 send cadence). Each lands alongside its required schema columns in the next iteration.
- **Phase 3 meta-classifier**: multi-signal correlation → `REBRAND_OR_MIGRATION` / `COMPROMISE_SHAPED` / `CONTENT_ONLY_DRIFT` / `AMBIGUOUS` classification on top of individual findings.
- **Phase 3 positive-drift suppression**: DMARC policy upgrades, preheader gains, one-click compliance gains stay silent in Phase 1 rather than being reported as `INFO: improving`.
- **Phase 4 ship-soon** (D13–D19): Message-ID host drift, subject-style Mann-Whitney, body-length distribution shift, language change, preheader-presence drop, audit-score trendline, template-engine fingerprint change.

---

## 14. What Step 1 explicitly does not yet do (deferred to BACKLOG)

So the consultant has a complete picture of the gap between current PoC and the full product vision:

- **Spamhaus DBL / SURBL / URIBL / Safe Browsing** — no DNS lookups on URL hostnames yet. Consultant flagged this as next-up (requires `dnspython`, network latency, rate-limit handling).
- **`tldextract` upgrade for eTLD+1 parsing** — current stdlib approximation in `link_quality` is ~90% accurate on common TLDs. Rare multi-label public suffixes may misclassify.
- **Live RFC 8058 unsubscribe POST** — we check headers/body for unsubscribe presence but don't POST the URL to verify it returns 200 without auth.
- **From-header sanity** — display-name vs address comparison with `parseaddr`. Classic phishing catch (display "PayPal Security", actual address random).
- **SpamAssassin integration** — not wired.
- **Message-ID / Date / Reply-To sanity** — no format / temporal / MX-resolution checks.
- **Subject heuristics** — no ALL-CAPS or excessive-punctuation detection.
- **Language-aware homoglyph aliases** — `preferred_aliases=["latin"]` hardcoded; will false-positive on non-English newsletters.
- **Alt-text coverage on `<img>`** — not checked; accessibility-adjacent quality signal.
- **Apple Intelligence preheader pre-empt** (iOS 18+) — front-load value in first ~100 body chars. Not checked.
- **iOS Link Tracking Protection** — warn when tracking params exist that will get stripped.
- **Non-ASCII byte-bloat** — UTF-8 multi-bytes push HTML toward the clip limit faster than `len()` suggests.

Full deferred list with triggers is in `BACKLOG.md`.
