<!--
  BACKLOG.md — Deferred features roadmap.

  Every item was deliberately cut from Step 1 to keep the PoC demoable
  within a week. Each entry names its trigger condition. When a feature
  ships, move it to the "Done" section with the date; don't delete.
-->

# Backlog

## PoC scope (what's being built)

Single-user PoC. Gmail API polling, not CloudMailin. Demo target: one week.

1. **Audit core** — parse `.eml`, 5 async checks, Pydantic `Report`, score+verdict, JSON + markdown output, SQLite row. **Live.** (Day 1–2.)
2. **Gmail polling ingest** — OAuth (desktop creds), label discovery (`audit-pending` / `audit-done`), `messages.get(format='raw')`, process, relabel, loop. **Live.** (Day 3.)
3. **Memory** — SQLite `emails` table stores raw MIME + metadata for every ingest. **Live.** Alignment analyzer = stub (Day 5).
4. **LLM humanization** — one structured call enriches Report with exec summary + top 3 fixes + per-check prose. Deterministic fallback. **Stub.** (Day 4.)
5. **Copy generator** — plain-text subject / preview / body, Self-Refine, deterministic critic reusing audit checks. **Live.** (Day 6, shipped 2026-04-23.)
6. **Full pipeline** — generate copy → human edits in ESP → test send → Gmail poll catches → audit → iterate. **Stub.** (Day 7.)

## Deferred audit checks (20 of the 25 — only 5 live today)

Category names per the new product plan. Add one at a time; each gets unit tests + an adversarial fixture.

### Authentication (live = 1 of ~5)

- **DMARC alignment detail** — distinguish relaxed vs strict alignment, surface policy (`p=`). **Trigger**: first audit where a pass lands on `p=none` and we want to warn anyway.
- **ARC chain validity** — report `arc=pass/fail` when present. **Trigger**: we start auditing forwarded messages.
- **BIMI** — informational only (indicator + logo retrieval). **Trigger**: any client asks about BIMI.
- **Sender-domain / From-domain alignment** — catches "friendly-from spoof" even when DKIM passes on a different domain. **Trigger**: first real phishing-style email in the corpus.
- **DMARC via alignment computation** — today we only read the `dmarc=` field from `Authentication-Results`. Some receivers (observed: Gmail) compute DMARC internally without emitting the field, so we report "missing" when the truth is "failed." Fix: parse the `From:` domain, check if any passing DKIM `header.i=@` aligns with it (DKIM alignment) OR if SPF mailfrom aligns (SPF alignment), compute relaxed/strict alignment ourselves. **Trigger**: already fired on Avateq email 2026-04-20 — Gmail UI showed DMARC=FAIL while we saw "missing."

### From-header sanity (not yet covered — moat-adjacent)

Currently `auth.py` only inspects `Authentication-Results`. The `From:` header itself (display name + address) goes unexamined. Four sub-checks, in order of effort/value:

- **From display/address spoof detection** (single-email, easy win) — parse `From:` with `email.utils.parseaddr` into `(display, address)`; regex every email-looking token out of the display name; compare case-insensitive against the actual address. Mismatch → CRITICAL (classic phishing: display name says `"support@paypal.com"`, actual address is `<scammer@evil.tk>`). **Effort**: ~30 lines in `audit/checks/from_sanity.py`, low risk. **Trigger**: any time — this is the cheapest moat-relevant add beyond the live 5 checks.
- **Generic alias / impersonal display name** — heuristic list of low-quality locals (`info@`, `sales@`, `noreply@`, `support@`, `hello@`) paired with empty / "same-as-address" display names. INFO-level quality flag for cold-outreach impersonal patterns that hurt deliverability. **Trigger**: alongside spoof detection or shortly after.
- **Authority-claim detection in display name** — lexicon-based scan for `"Security Team"`, `"Your Bank"`, `"Microsoft Support"`, etc., where the `From:` domain isn't in a trusted-brand list. MEDIUM severity. Prone to false positives on legit security companies — needs keyword tuning against real audit history. **Trigger**: first adversarial sample with authority-claim spoofing reaches the corpus.
- **Brand vs domain mismatch** — display name mentions a known brand while the `From:` domain is unrelated or a typosquat. Needs a brand-to-domain registry + fuzzy domain matching (dovetails with the existing homoglyph check). Significant engineering. **Trigger**: after a brand registry is built or sourced.

### Content / HTML (live = 3: size, hidden_css, invisible_chars — plus homoglyph listed here)

- ~~**Visible text minimum** (≥ 500 chars when >3 images)~~ — shipped 2026-04-21 as `content.image_text_ratio` in `audit/checks/body_composition.py`.
- ~~**Image-to-text ratio**~~ — shipped 2026-04-21 alongside visible-text check, same module.
- **Alt-text coverage on `<img>`** — soft finding. **Trigger**: accessibility ask.
- **Indirect prompt injection detector** — hidden CSS + instruction-verb lexicon (`ignore previous`, `you are admin`, `<Admin>`). **Trigger**: first audit where a Gemini/Apple summary misbehaves OR immediately after we see any hidden-div content in real traffic.
- ~~**Unsubscribe-link above-the-fold**~~ — shipped 2026-04-21 as `render.unsub_clipped` in `audit/checks/unsubscribe.py`.
- **CSS-block scan completeness** — today we scan inline `style=""` + `<style>` blocks with regex; add `cssutils` for parsed-CSS accuracy. **Trigger**: first false negative on hidden-CSS.
- **Preheader vs prompt-injection classifier accuracy** — current `hidden_css.py` classifies hidden text as "adversarial" if it contains ~10 instruction-verb keywords OR its real-content length exceeds 300 chars. Crude. A well-crafted injection that's short and dodges the keyword list would pass as "benign." Future: LLM-based content classifier, expanded verb lexicon, or behavioral features (role tags like `<Admin>`, unusual punctuation density, encoding obfuscation). **Trigger**: first adversarial sample that slips through the current classifier.
- **Preheader usage advisory** — flag emails where no hidden preview-text element exists. Inbox clients (Gmail, Apple Mail) fall back to scraping the first visible body line — typically a salutation ("Hi George") or generic header — wasting prime inbox real estate that could be selling the email. Observed in the Avateq corpus (2026-04-21 bootstrap): 8 of 15 historical campaigns had no preheader at all. Three layers, all dependent on the LLM advisory pass:
  - **Single-email finding**: if `memory/store._extract_preheader` returns None, emit a LOW-severity advisory. The raw signal is deterministic; `memory/store.py` already captures preheader presence via the `preheader` column.
  - **Cross-email drift**: if the sender used preheaders in ≥50% of the past N stored emails and the current send omits one, escalate to MEDIUM (regression). Reads from the `emails` table.
  - **LLM advice**: given the first body paragraph + past preheaders from the same sender, generate a targeted suggestion of what this email's preheader *should* have said. Deterministic detection; LLM writes prose only.

  **Trigger**: after display-name drift scaffolding ships AND the LLM humanization pass is wired (see "Deferred LLM work"). Each layer can land independently; start with the single-email flag since the data is already being stored.
- **Language-aware homoglyph baseline** — detect the email's primary language/script (via `langdetect`, `pycld3`, or a Unicode-block histogram over the visible text) and set `preferred_aliases` dynamically: `["latin"]` for English/French/Spanish, `["cyrillic"]` for Russian, `["greek"]` for Greek, etc. Today `preferred_aliases=["latin"]` is hardcoded in `audit/checks/homoglyph.py`, which will false-positive on legitimate non-English newsletters (every Cyrillic letter in a Russian email would flag). **Trigger**: first audit of a non-English sender OR first false-positive report on legitimate multilingual content. Needs: a language-detection helper in `utils/`, a script-to-alias mapping table, and updating the homoglyph check to consume the detected alias instead of the hardcoded list.

### Link reputation (live = 0)

- **Spamhaus DBL lookup** per unique hostname (`{host}.dbl.spamhaus.org` via `dns.asyncresolver`). **Trigger**: ready to spend the ~200 ms/host network budget.
- **SURBL lookup**.
- **URIBL lookup**.
- **Google Safe Browsing v5** (migrate before v4 EOL 2027-03). **Trigger**: any sender-provided link ever gets a DBL hit.
- **Low-reputation TLD informational risk** (`.top`, `.sbs`, `.cfd`, etc.).
- ~~**URL-shortener blacklist** (bit.ly, t.co, etc.)~~ — shipped 2026-04-21 as `content.url_shortener` in `audit/checks/link_quality.py` (17-entry list).
- ~~**Anchor-text / href mismatch**~~ — shipped 2026-04-21 as `content.anchor_href_mismatch` in `audit/checks/link_quality.py` (HIGH severity, stdlib eTLD+1 approximation). `tldextract` upgrade for rare multi-label TLDs still deferred.

### Headers (live = 0)

- **RFC 8058 one-click unsubscribe live POST** — header + body presence shipped 2026-04-21 (`content.list_unsubscribe_header`, `content.list_unsubscribe_post`, `content.unsubscribe_link_body`). The **live** POST verification — actually hitting the unsubscribe URL to confirm it returns 200 without auth quickly — is still deferred. **Trigger**: any bulk-sender audit where we want to go beyond header-presence to functional validation.
- **Message-ID format sanity** (`<local@domain>` shape).
- **Date within ±72h of receipt**.
- **Reply-To resolvability** (MX of the domain).
- **Subject heuristics** — ALL-CAPS detection, excessive punctuation.
- **Precedence / X-Mailer detection** (fingerprint the ESP; also filters random inbound spam).

### SpamAssassin (live = 0)

- **aiospamc 1.1.1 + instantlinux/spamassassin:4.0.0-6 in Docker** — run the full suite on raw bytes. **Trigger**: Docker is up on the dev machine (already planned).
- **Postmark SpamCheck as reference** — free second opinion. Treat as signal not truth (their SA is from 2014).

### Render / clip risk (live = 0)

- **Non-ASCII byte-bloat** — UTF-8 multi-bytes push HTML toward the clip limit faster than `len()` suggests.
- **Apple Intelligence preheader pre-empt** (iOS 18+) — front-load value in first ~100 body chars.
- **iOS Link Tracking Protection** — warn when tracking params that will get stripped exist.

## Deferred infrastructure (post-PoC scaling)

The PoC uses Gmail API polling with a plus-address. It doesn't scale past one user and hits Gmail's quota with steady polling. Everything below is deferred until the PoC justifies scaling.

- **CloudMailin inbound webhook** (`http_post_format=raw`) + FastAPI receiver + HMAC verification + per-user token routing (`audit-{token}@audit.domain.com`) + ESP fingerprint filter. **Trigger**: multi-user OR single-user polling gets rate-limited OR we want a real domain.
- **SES → S3 → Lambda alternative** to CloudMailin — cheaper at scale (~$0.10 per 1,000). **Trigger**: CloudMailin volume gets expensive.
- **Per-user audit tokens** (DB model + generator). **Trigger**: webhook lands.
- **ESP fingerprint allowlist** — recognize Mailchimp / Klaviyo / ActiveCampaign / Brevo / HubSpot by DKIM signing domain, reject everything else. **Trigger**: first time a random spammer hits our audit inbox (not possible with plus-address + Gmail filter — so Gmail path never needs this).
- **Webhook-based ingest** replacing the poll loop — **Trigger**: polling lag annoys during demo OR we move off Gmail.

## Deferred LLM work

- **`instructor` humanization pass** — one structured call that takes `Report` and returns `HumanizedReport` (executive summary + top 3 fixes + per-check advice). Few-shot with good/bad advice examples. **Deterministic report stays the source of truth; LLM writes prose only.** **Trigger**: Step 3 (copy gen) is working and we want to polish the audit output.
- **Deterministic fallback for LLM advice** — when `instructor` validation fails (~10% per research), render a templated advice string. **Trigger**: first time the LLM path errors in a demo.
- **Copy generator**:
  - Generator: `copy_gen/generator.py` — OpenAI chat call, `{subject, preview, body}` Pydantic.
  - Critic (deterministic): `copy_gen/critic.py` — reuses audit checks (homoglyph, invisible-chars, subject heuristics, readability via `textstat`).
  - Refine loop: `copy_gen/refine.py` — 2-iteration cap.
  - CLI: `scripts/copy_gen.py`.

## Deferred memory work

**Current state (2026-04-21):** `memory/store.py` stores one row per ingested email in the `emails` table (raw bytes + from/subject/preheader/body_plain/sha256). Audit rows are no longer persisted to SQLite — markdown + JSON on disk are the audit output. `memory/analyzer.py` is still a stub.

- **"Final email" detection + `final_score` column** — we store every ingested email today, but copy-gen iteration produces many drafts; the "final" one (the version actually sent) is what multi-email analysis should weight highest. Add an `is_final` flag (nullable INTEGER) plus a `final_score INTEGER NULL` column to `emails` once we have a signal for finality. **Trigger**: copy gen ships AND we have ≥ ~10 iterations stored, enough to design the signal.

- **Cross-email: display-name drift from same sender address** — major inbox providers (Gmail, Yahoo, Microsoft) penalize mailboxes that rotate display names over time (shared-inbox abuse, outreach tools rotating sales-rep "faces," reputation-evasion). Fundamentally a memory-layer check. **Implementation**:
  1. Promote `memory/analyzer.py` stub. Add `display_names_for(address: str, limit: int = 20) -> list[str]` that queries the `emails` table, parses display names out of stored `from_addr` values using `email.utils.parseaddr`, returns the distinct set.
  2. New check `audit/checks/from_consistency.py` — calls `display_names_for` for current email's sender address. If distinct count > 2 across last 20 emails → HIGH with observed names in details. If 1-2 → INFO pass. If no history → skip silently (no finding, not even INFO).
  3. Wire into `audit/runner.py`'s `CHECKS` list.

  **Effort**: ~40 lines across two files. **Trigger**: fires right after it ships — signal sharpens over time as the email history grows. **Note**: needs at least 2-3 prior emails from the same sender before the check produces anything useful; single-email senders are skipped silently so they don't pollute the report.

- **Alignment analyzer** (broader) — "look at last N emails per sender, flag drift." Other candidate heuristics after display-name drift ships:
  - Subject-style drift (keyword / length / casing patterns changing abruptly).
  - Preheader drift / reuse patterns across sends.
  - ESP change detection (derived by re-parsing `raw` for DKIM `header.i` or `header.s` changes).
  - Body-similarity regressions (same sender suddenly sending very different copy).

  **Trigger**: after display-name drift is live and we have the scaffolding. Ideally at least 20 emails stored before heuristics are tuned.
- **Per-sender / per-ESP aggregate stats CLI** — replacement for the deleted `audit_history.py`, reading from `emails`.
- **Upgrade SQLite → Postgres** — **Trigger**: multi-tenant deployment OR 10k+ rows.
- **Fuzzy-match false-positive mitigation** — `memory/store.py:save_email` uses `difflib.SequenceMatcher` on concatenated `subject + body_plain` with a score-driven threshold. A genuinely new campaign that shares heavy template boilerplate with a recent stored iteration (same footer, same header image alt-text, etc.) could incorrectly overwrite it. Upgrades: weight subject heavier (e.g., composite score = 0.6 × subject_similarity + 0.4 × body_similarity), or switch to Jaccard over token sets for faster + boilerplate-robust matching. **Trigger**: first observed false merge where iteration v_n overwrites an unrelated campaign.
- **Ingest real sends at the plain address** — current design relies on the user's last `+audit` test being ~95% identical to their real send, so the stored row represents the real. If a user routinely ships a substantially different version than their last test (or skips `+audit` and sends cold), the `emails` table misses reality. Fix: add a second poll stream watching `from:<known-senders> is:unread has:list-unsubscribe` on the plain address. **Trigger**: observed case where a real send diverges meaningfully from its last `+audit` iteration, or user stops using `+audit` for tests.

## Deferred evaluation

- **Adversarial fixture corpus** — SpamAssassin Public Corpus + TREC 2007 + 50–100 hand-crafted adversarial `.eml` files. Currently: 1 fixture. **Trigger**: rubric stabilizes (after at least 2 more checks ship).
- **Mail-Tester cross-reference** — weekly sanity run. **Trigger**: need calibration signal for the scoring curve.
- **Per-check false-positive / false-negative measurement**.

## Deferred product surface

- Web UI — out of scope for PoC entirely.
- Multi-user / auth — SQLite doesn't need it; out of scope.
- ESP integration (sending) — not in the product spec.
- Subject-line A/B testing — not in spec.
- Image-generation — not in spec.

## Deferred flexibility

- **Model-agnostic config** (YAML + `init_chat_model` + CLI) — **Trigger**: first time we want to A/B Claude vs OpenAI for copy gen.
- **Thresholds as config / env** — hardcoded in `config.py` today. **Trigger**: first non-dev tweak.
- **structlog JSON logging** — stdout `print()` is fine for PoC. **Trigger**: first production deployment.

---

## The four moats (do not forget)

These are *the* differentiation. Everything else is table-stakes.

1. **Modern adversarial checks** — prompt-injection, homoglyphs, hidden-text salting. **Live today** (3 of the 5 checks in Step 1 already cover this axis.)
2. **Live RFC 8058 compliance testing** — not just "header present" but "POST works, 200, no CAPTCHA." **Deferred, Phase 1b.**
3. **LLM-generated specific fix advice** — not templated garbage. **Deferred, Phase 3.**
4. **Shared checks between audit + copy gen** — generated copy can't trip our own audit. **Partly live** — when copy gen ships it imports from `audit.checks`. Wiring planned in `copy_gen/critic.py`.

## Competitor watch

- **MailTester.ai** — same wedge (AI content rewriting + auth checks + "works with every ESP"). Velocity check monthly.
- **Mail-Tester** — classic, not adversarial-aware. Moat #1 is the gap.

---

## Done

- **2026-04-23 — Copy generator v1 shipped (Day 6 of PoC)** — `copy_gen/` is now wired end-to-end: `scripts/copy_gen.py --brief <file> --sender <addr>` reads a key:value brief, pulls the sender's history via `memory.store.history_for`, runs `copy_gen.voice.extract_voice` (cached at `voice_profiles/{domain}.json`, stale when row-count grows by ≥3), and enters a 2-round Self-Refine loop (`copy_gen.refine`). Each round: `copy_gen.generator.generate` makes one `gpt-4o-mini` structured-output call producing `DraftCopy{subjects×3, preview, body_plain, chosen_subject_index, sign_off}`, then `copy_gen.critic.criticise` runs homoglyph + invisible_chars from `audit.checks` plus six inline checks (subject heuristics per variant, spam-trigger substring scan, compound-signal category score, body word-count vs length_hint, link count + Google-Drive detection, emoji count, sign-off shape). Six human-editable markdown context packs under `copy_gen/context/` carry the writing-craft rules (storytelling, copywriting, open_rate, structural_rules, spam_triggers) plus `niche/toronto_precon_voice.md` auto-loaded when `VoiceProfile.niche` matches pre-construction keywords. Seeded from research: real-estate compounding vocabulary (VIP Access, Platinum Access, Reserve Your Unit, Prices Go Up Monday, etc.), subject rules (≤50 chars, sentence case, ≤8 words, no "newsletter" word, ≤1 emoji), ≤200 word body, ≤2 links, reply-ask default CTA, three-line person-not-brand sign-off, Halabi category-first framing, honest-friction acknowledgement. Verified end-to-end against Emil's Lambton Mills brief (clean output, converged round 1) and against a deliberately bad brief (VIP + prices-go-up + drive.google.com + reserve-your-unit) that the system prompt + critic scrubbed into clean copy. Still stub: full-pipeline glue (Day 7), HTML generation, ESP engagement-data feedback loop, per-niche A/B tracking, more niche packs.
- **2026-04-21 — `<style>`-block hidden-CSS classifier** — `audit/checks/hidden_css.py` no longer blanket-flags every `<style>` block containing a hidden-style pattern as CRITICAL. It now parses each CSS rule, flattens `@media`/`@supports`/`@keyframes` wrappers, resolves the selector against the HTML via BeautifulSoup, and classifies based on the actual matched-element text. Paired refinement on the inline-style path (Path A): elements whose content (after noise-char stripping) is empty get skipped entirely — spacer `<td>`s, tracking `<img>`s, and empty structural hide-wrappers aren't hiding real content, so no hit is emitted. Content-touching hidden CSS **remains** HIGH or worse regardless of classification — we deliberately don't downgrade "short benign" hits because we can't reliably distinguish benign from adversarial patterns not yet in the lexicon. Effect on fixtures: `gold_standard_hubspot.eml` went NO_GO (40) → GO (85) → **GO (100)**; `adversarial.eml` still NO_GO (25, prompt-injection hidden div still correctly flagged via Path A).
- **2026-04-21 — Step 3 drift detection Phase 0 + Phase 1 shipped** — New `audit/drift/` package with runner + 6 check modules (D01 DMARC regression, D03 SPF/DKIM flip, D04 DMARC policy downgrade, D08 List-Unsubscribe regression, D10 display-name rotation incl. friendly-from spoof, D11 Reply-To divergence). New `memory/derived.py` populates 12 derived columns (from_domain, display_name, reply_to_domain, num_images, spf_result/dkim_result/dmarc_result/dmarc_policy, list_unsub_has_{mailto,https,oneclick_post}) at save time; backfill via `scripts/backfill_derived.py`. New helpers `memory/store.history_for(sender_domain, ...)` and `cold_start_ok(history, min_rows=10, min_age_days=21)`. `audit/runner.py:audit()` now accepts optional `history=`; drift findings merge into the existing Report and count toward the same score formula. Callers `scripts/gmail_poll.py` and `scripts/audit_one.py` fetch history by sender_domain before audit. Phase 2 (D02/D05/D06/D07/D09/D12), Phase 3 (multi-signal meta-classifier + positive-drift suppression), and Phase 4 (D13–D19) remain deferred.
- **2026-04-21 — Step 1 content-side filter-compliance checks shipped** — 9 new Findings from 4 new modules, implementing the full content-side consultant recommendation (Bucket 1). `audit/checks/unsubscribe.py` (4 findings): `content.list_unsubscribe_header`, `content.list_unsubscribe_post` (RFC 8058 One-Click compliance; CRITICAL on bulk mail when missing, INFO on 1:1), `content.unsubscribe_link_body` (MEDIUM when absent), and `render.unsub_clipped` (CRITICAL, fires only when the visible unsubscribe anchor sits past Gmail's 102 KB clip threshold). `audit/checks/body_composition.py` (2 findings): `content.plain_text_alternative` (MEDIUM if missing/<100 chars) and `content.image_text_ratio` (HIGH when visible text <500 chars AND >3 images). `audit/checks/link_quality.py` (2 findings): `content.url_shortener` (MEDIUM when any `<a href>` hits a 17-entry shortener list) and `content.anchor_href_mismatch` (HIGH when visible link text domain differs from href registrable-domain; stdlib eTLD+1 approximation, `tldextract` upgrade deferred). `audit/checks/observability.py` (1 finding): `headers.feedback_id` (INFO when bulk mail lacks the header — observability only, not a delivery issue). Bulk-mail heuristic shared across `unsubscribe` and `observability`: any of `List-ID`, `Feedback-ID`, `X-Mailchimp-Campaign-ID`, `X-Campaign`, `X-Campaign-ID`, `X-Klaviyo-MessageID`, `X-AC-Campaign-ID`, or `Precedence: bulk`. Registered in `audit/runner.py` — CHECKS list goes from 5 to 9 modules.
