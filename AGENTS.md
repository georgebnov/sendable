# SYSTEM — single source of truth

This file describes **everything the program does today.** Anything not
in this file is either roadmap (`TODO.md`) or deferred (`docs/BACKLOG.md`).
If code disagrees with this file, the code is right and this file is
stale — file an issue and update it.

> **Current MVP push (2026-05):** the audit engine is feature-complete
> for v1. Next milestone = wrap it in a web UI so the tool can be used
> outside a terminal. Backend = FastAPI, frontend = HTMX server-rendered.
> Auth = Google OAuth (reuses existing `gmail_ingest/auth.py`). No ESP
> integration, no engagement ingestion, no domain config — Google sign-in,
> drag-drop `.eml`, see report. Future steps live in `TODO.md`.

---

## What this tool actually is

**A pre-send audit for anyone who needs their emails to land in the
inbox, protect sender reputation, and actually get opened.**

Audience: founders, agencies, sales reps, real-estate agents,
newsletter operators, indie senders — anyone who sends email and
treats deliverability + reputation + open rate as table stakes, not
optional.

The tool answers three questions on every test send:

1. **Will this email be delivered?** SPF / DKIM / DMARC / alignment,
   live domain-health probe (DNS, SMTP, RBL, URL reputation), Gmail
   spam-folder check, hard gates that force NO_GO when delivery is
   at risk.
2. **Is sender reputation safe?** Domain RBL listings, URL-host
   reputation, SMTP-MX banner health, MTA-STS / TLSRPT / BIMI
   posture, drift checks (DMARC regression, auth flip, policy
   downgrade, display-name rotation, Reply-To divergence) versus
   prior sends from the same sender.
3. **Will this email get opened?** Subject heuristics with measured
   open-rate effect sizes, preheader / preview-text quality,
   compound-signal spam-trigger score, copywriting rules from the
   open-rate research pack, hidden-text / homoglyph / invisible-char
   adversarial checks, link-quality + anchor-href mismatch.

Workflow:

1. Build a campaign in any ESP (Mailchimp, Klaviyo, Kit,
   ActiveCampaign, HubSpot, etc.).
2. Fire a **test send** to a Gmail plus-address
   (`youraddress+audit@gmail.com`).
3. Tool catches the test, runs ~40 deterministic checks plus the
   live domain-health probe, scores it, writes a plain-English
   markdown report — what's wrong, why it hurts delivery /
   reputation / open rate, and how to fix it in the ESP composer
   **before** the campaign goes to the full list.

Loop: build → test send → audit → fix → re-send → repeat until
verdict = GO. Then send to the real list.

**Second agent** (copy generator) writes the test email from a brief
if no draft exists yet. Same rule library — generated copy cannot
trip its own audit.

### Out of scope (today)

- Not a full inbox/email-analysis platform.
- Not a lead CRM.
- Not a multi-agent orchestrator.
- Not a SaaS — single-user CLI, single SQLite file, Gmail polling.
- Doesn't ingest open/click/reply/unsubscribe rates from your ESP.
- Doesn't do A/B test orchestration.
- No HTML rendering — plain text body only; ESP wraps the template.

Roadmap items (lead enrichment, scoring, dashboards, FastAPI, Postgres,
CloudMailin) live in `TODO.md` and `docs/BACKLOG.md`. They are not
shipped.

---

## Test mode vs production mode

Most users will run audits on **test sends** — emails that haven't
gone to the real list yet. Test sends have markers production sends
don't: `TEST -` subject prefix, ESP test headers, raw `[FIRST NAME]`
merge tags. Scoring those at face value would be wrong (every test
send would fail the "unfilled merge tag" check). So the audit detects
mode and cleans the email before scoring.

**Detection** (`audit/mode.py`): defaults to TEST when ambiguous.
Signals — any one of:

- ESP test header (`X-Mailchimp-Test`, `X-Mailgun-Test`, `X-Klaviyo-Test`,
  `X-HubSpot-Test`, `X-Sendgrid-Test`, `X-AC-Test`, `X-Brevo-Test`,
  `X-Mailin-Type: template-test`, `X-Test`, `X-Preview-Send`)
- Subject prefix matching `TEST -`, `[PREVIEW]`, `SANDBOX:`, `DEV:`,
  `STAGING:`, `DRAFT:`, `QA:`, `UAT:`
- Recipient is a plus-address (`+audit@`, `+test@`, `+preview@`,
  `+qa@`, `+staging@`, `+dev@`)
- Body contains unrendered merge tags (Jinja `{{ first_name }}`,
  Liquid blocks, Mailchimp `*|FNAME|*`, ActiveCampaign `%FIRSTNAME%`,
  `%%first_name%%`, manual `[FIRST NAME]`, double-bracket `[[ x ]]`)

CLI override: `--mode test|production`. Auto-detection wins by default.

**Cleanup** (`audit/cleanup.py`, only on TEST):

- Strip test prefix from subject (e.g. `TEST - Big news` → `Big news`)
- Drop ESP test headers entirely (won't exist in real send)
- Substitute merge tags with realistic fakes:
  - First-name fields → random pick from `Sarah / Marcus / Priya /
    Ahmed / Emma / Noah / Léa / Kai`
  - Last-name → `Chen / Patel / Garcia / Kowalski / Okafor / Müller`
  - Email → `sarah.chen@example-recipient.com`
  - Company / city → `Northwind Realty` / `Toronto`
  - Unsub URL → `https://list.example.com/unsubscribe?token=fakeUnsub123`
  - Generic link / "view in browser" → `https://www.example.com/landing?utm_source=audit`

Cleanup is **idempotent** and safe on production emails (no-op if no
test markers). Original `.eml` is stored unchanged in SQLite memory;
only the in-memory `ParsedEmail` is mutated. Drift checks see ORIGINAL
headers (drift compares real send to past real sends).

**`Report.mode`** (`ModeInfo`): every Report carries the detected
label, fired signals, and exact cleanup actions. The report renderer
+ stderr summary surface this so the user sees how their test was
projected to production.

---

## The two agents

### Agent 1 — Audit

**Purpose:** grade one `.eml` against delivery, reputation, and
open-rate failure modes — then tell the sender how to fix each issue
in their ESP composer.

**Entry points:**

| Command | What it does |
| --- | --- |
| `python3 scripts/audit_one.py path/to/file.eml` | Audit one local `.eml`. |
| `python3 scripts/gmail_poll.py` | Watch a Gmail label, auto-audit any new test send. |

**Inputs:**
- One raw `.eml` (MIME bytes).
- Optional sender history from `audits.db` SQLite (drift checks
  activate at ≥3 prior rows; D10 needs ≥8).

**Outputs:**
- `reports/audit_<ts>.md` — humanized report (what's wrong + what to do).
- `output/audit_<ts>.json` — raw structured findings.
- One row in `audits.db` with raw bytes + 12 derived columns.

**Data flow (`scripts/audit_one.py` → `audit/runner.py`):**

1. `parse_eml(raw)` → `ParsedEmail` (`audit/parse.py`).
2. **Mode detection** (`audit/mode.py`) — heuristic test-vs-production
   classifier. Defaults to TEST when ambiguous. Signals: ESP test
   headers (`X-Mailchimp-Test`, `X-Mailgun-Test`, `X-Klaviyo-Test`,
   `X-HubSpot-Test`, `X-Sendgrid-Test`, `X-Mailin-Type: template-test`,
   …), subject prefix (`TEST -`, `[PREVIEW]`, `SANDBOX:`),
   plus-address recipient (`+audit@`, `+test@`), unrendered merge tags
   in body. CLI override: `--mode test|production`.
3. **Cleanup** (`audit/cleanup.py`, only on TEST) — transforms the
   test send into a production-shaped email so the audit scores what
   real recipients would receive:
   - Strip test prefix from subject (`TEST -`, `[PREVIEW]`, …)
   - Drop ESP test headers
   - Substitute merge tags with fake-but-real values (Sarah, Marcus,
     Priya …; URL placeholders get URL-shaped fakes; supports Jinja /
     Liquid / Mailchimp `*|FNAME|*` / ActiveCampaign `%FIRSTNAME%` /
     manual `[FIRST NAME]` / etc.)
   - Cleanup actions tracked in `Report.mode` for transparency
4. `asyncio.gather(...)` runs all per-email checks on the **cleaned**
   email (or original on PRODUCTION mode).
5. If history is provided → `run_drift(parsed, history)` runs 6 drift
   checks against the **original** parsed email (drift = how this real
   send compares to past real sends; cleaned headers would lie).
6. If `domain_health=True` (default) → `run_domain_health(cleaned)`
   does live DNS + SMTP + HTTP probes against the sender's domain.
7. If `probe_unsub=True` (opt-in via `--probe-unsub`) →
   `unsubscribe_live.run` actually POSTs `List-Unsubscribe=One-Click`
   to the unsub URL, follows up to one redirect, verifies 2xx. Off
   by default — may trigger a real unsubscribe on third-party lists.
8. If receiving Gmail mailbox routed the message to Spam, append a
   HARD-GATE finding capping score at `SPAM_SCORE_CAP=50`.
9. `score_findings(...)` → Rspamd-style group-capped composite with
   hard gates (`audit/scoring.py`).
10. `humanize(report, parsed, …)` — one OpenAI `gpt-4o-mini` structured
    call rewrites failing findings into plain-English advice with
    composer-UI fix chips: ✏️ user-can-fix, 🛠️ tool-workaround,
    🌐 needs-DNS.
11. `save_email(raw, parsed, score)` — SQLite memory stores **original**
    bytes (not cleaned) with iteration-collapse fuzzy match.
12. Render markdown + JSON + stderr summary. Stderr surfaces detected
    mode, signals, and cleanup actions taken.

#### What gets checked

**ESP detection** (`audit/esp/`) — runs once per audit. Cascade: vendor
header (≈0.95) → `Feedback-ID` token (≈0.9) → DKIM `d=` domain (≈0.75) →
List-Unsubscribe host marker (≈0.7) → footer-chrome substring (≈0.55).
Profiles for Kit, Mailchimp, Klaviyo, SendGrid, HubSpot, ActiveCampaign,
Brevo, Mailgun, Campaign Monitor, Constant Contact. Confidence ≥ 0.6
gates downstream demotion. `Finding.source` carries the attribution
(`user_content` / `esp_template` / `domain_config`) so the renderer can
group "what you can fix" vs "what your sending tool injects" vs "what
your domain admin owns."

**Test→production cleanup** (`audit/mode.py` + `audit/cleanup.py`) — runs
before the per-email checks when test signals fire (ESP test header,
`+audit@` plus-address, TEST: subject prefix, unfilled merge tags
anywhere on body / subject / From display name / Reply-To). Strips test
subject prefix + ESP test headers, substitutes merge tags with fake-real
values. Merge-tag coverage: Jinja `{{…}}`, Liquid `{%…%}`, Mailchimp
`*|…|*`, ActiveCampaign `%FOO%`, double-percent `%%foo%%`, double-bracket
`[[…]]`, plus a keyword-gated single-bracket sniffer that catches Kit's
`[FIRST NAME GOES HERE]`, Campaign Monitor `[firstname,fallback=friend]`,
and Constant Contact `[Recipient FirstName]` while preserving MSO
Outlook conditionals (`[if mso]`/`[endif]`). Address halves of From / To
/ Reply-To headers are kept exact so SPF/DKIM/DMARC alignment checks
still see the real domain.

**Per-email checks** (run in `audit/checks/`, registered in
`audit/runner.py` `CHECKS` list):

| File | What it looks at |
| --- | --- |
| `auth.py` | SPF / DKIM / DMARC / ARC / BIMI methods reported by `Authentication-Results`. |
| `alignment.py` | DMARC alignment reasoning, Return-Path domain, Reply-To registrable-domain divergence vs From. |
| `header_hygiene.py` | Required headers, no-duplicate headers, Date drift (7-day window), Message-ID well-formed (`<local@domain>`). |
| `microsoft_eop.py` | Microsoft EOP signal parsing (SCL / BCL / SFV codes / compauth verdict). |
| `subject.py` | Subject heuristics (length, case, punctuation, emoji, Re:/Fwd:, newsletter-word, $-opener). |
| `body_composition.py` | Plain-text alternative presence, image-vs-text ratio, visible-text minimums. |
| `template_quality.py` | Empty `href`, unfilled merge tags, body-too-short, ESP test-send headers leaking through. |
| `hidden_css.py` | Hidden-text salting via real CSS selector resolution (handles `@media`, `@supports`, `@keyframes` wrappers). **ESP-aware** — benign hits on a high-confidence ESP profile (preview-text span, footer chrome) are demoted to INFO with `source="esp_template"`. Adversarial hits (instruction verbs / >300 chars) stay CRITICAL. |
| `homoglyph.py` | Cyrillic / Greek / mixed-script confusables (subject + body + link hosts). Latin-baseline only today. |
| `invisible_chars.py` | Zero-width chars (U+200B family) + bidirectional overrides (U+202D/U+202E). **ESP-aware** — body-only zero-widths on a high-confidence ESP profile are demoted to INFO with `source="esp_template"`. Subject hits stay HIGH (subject is user-controlled). Bidi overrides never demoted. |
| `link_quality.py` | URL shorteners (curated 17-entry list), anchor-text vs href-host mismatch. |
| `unsubscribe.py` | RFC 2369 `List-Unsubscribe` header, RFC 8058 `List-Unsubscribe-Post` *header presence*, visible body unsub link, position vs Gmail 102KB clip. |
| `unsubscribe_live.py` | **Opt-in.** Actually POSTs `List-Unsubscribe=One-Click` to the unsub URL, follows up to one redirect (ESP proxy → real backend), verifies 2xx. Network failures degrade to INFO. Off by default — enable with `--probe-unsub`. |
| `attachment_risk.py` | Risky attachment extension detection. |
| `size.py` | HTML byte size, Gmail 102KB clip threshold, missing HTML part. |
| `observability.py` | `Feedback-ID` header for Gmail Postmaster Tools, `Precedence: bulk`. |
| `copywriting.py` | Re-runs the copy critic's rules (subject, spam triggers, compound-signal score, body length, link count, Drive link, shouting, emoji, sign-off, newsletter-word). |

**Drift checks** (require sender history; in `audit/drift/`):

| Check | Detects |
| --- | --- |
| `d01_dmarc_regression` | DMARC went from pass → fail vs prior sends. |
| `d03_auth_flip` | SPF/DKIM pass-to-fail flip. |
| `d04_dmarc_policy_downgrade` | Policy moved `reject` → `none`. |
| `d08_list_unsub_regression` | Lost RFC 8058 one-click compliance. |
| `d10_display_name_rotation` | Sender renamed too often (≥8 rows). |
| `d11_reply_to_divergence` | Reply-To domain drift on bulk mail. |

**Live domain-health probes** (require network; in
`audit/domain_health/checks/`):

| File | Probe |
| --- | --- |
| `spf.py` | TXT lookup of sender domain → SPF record syntax. |
| `dmarc.py` | TXT at `_dmarc.<domain>` → policy + alignment + reporting. |
| `dkim.py` | TXT at `<selector>._domainkey.<domain>` → key bits, algorithm. Uses 25 common selectors when no DKIM-Signature present. |
| `modern_records.py` | MTA-STS (TXT + HTTPS policy file), TLSRPT, BIMI presence + record syntax. |
| `dns_infra.py` | NS records present. (SOA / multi-NS / serial-format checks removed — DNS-ops hygiene, not a deliverability signal.) |
| `blacklist.py` | IP RBL fan-out — Spamhaus ZEN, CBL, Barracuda + others; sentinel-aware NXDOMAIN handling to avoid public-resolver false positives. |
| `url_reputation.py` | Per-unique-body-host fan-out across Spamhaus DBL, SURBL, URIBL multi, ivmURI, Nordspam, SEM FRESH/URI/URIRED. |
| `smtp_probe.py` | Live MX probe — MX-shape sanity (bare IP / CNAME) + open-relay test. Inbound-MX banner / TLS / timing removed: those are operational metrics, not deliverability signals. |
| `sending_ip_dns.py` | PTR + FCrDNS on the actual sending IP (extracted from Received chain). This is the Gmail / Microsoft requirement — checking the MX IP was the wrong target. Demoted to INFO when sending IP belongs to a known ESP. |
| `sender_dbl.py` | Sender's own apex fanned out across the same 8 URL blacklists as `url_reputation.py` (Spamhaus DBL, SURBL, URIBL multi, ivmURI, Nordspam, SEM FRESH/URI/URIRED). A listing here forces CRITICAL + hard-gate — every major receiver junks DBL-listed senders regardless of content. |

> Removed: `web_server.py` (apex HTTP/HTTPS + cert chain probes). Website state has zero impact on inbox placement — Gmail / Yahoo / Microsoft do not check the apex web server when scoring outbound mail. If a body link points to a domain with a bad cert, `url_reputation.py` already catches the reputation side.

Every check emits PASS or FAIL with severity (`CRITICAL` / `HIGH` /
`MEDIUM` / `LOW` / `INFO`). The full rollcall — passed and failed —
shows in the report's "Technical breakdown" so you can see which
checks actually ran.

#### Scoring

`audit/scoring.py` — two-stage hurdle pipeline:

1. **Hard gates.** Any `CRITICAL` finding or finding with
   `hard_gate=True` caps composite at `HARD_GATE_FLOOR=30`. Forces
   `NO_GO`. Spam-folder placement caps at `SPAM_SCORE_CAP=50`.
2. **Per-category continuous score.** Findings auto-tagged by check
   prefix into 5 categories with weights and budgets:

   | Category | Weight | Budget | Routes |
   | --- | --- | --- | --- |
   | Authentication | 0.30 | 30 | `auth.*` |
   | Infrastructure | 0.25 | 30 | `smtp.*`, `blacklist.*`, `url_reputation.*`, `dns.*`, `http.*`, `https.*`, `delivery.*` |
   | Content | 0.20 | 30 | `content.*`, `copywriting.*`, `headers.*`, `microsoft_eop.*`, `render.*`, `size.*` |
   | Domain records | 0.15 | 30 | `spf_record.*`, `dmarc_record.*`, `dkim_record.*`, `mta_sts.*`, `tlsrpt.*`, `bimi.*` |
   | Engagement | 0.10 | 30 | `drift.*` |

   Severity penalties sum within a category, capped at the budget.
   Sub-score = `100 × (1 − capped_penalty / budget)`. Composite =
   weighted geometric mean across present categories. Engagement
   weight redistributes proportionally when no drift history exists.
3. **Soft multipliers** apply after composite.
4. **Verdict:** `GO ≥ 85`, `REVIEW ≥ 65`, else `NO_GO`.

Every `Finding` also carries a `source` field — `user_content` /
`esp_template` / `domain_config` — used by the renderer to group findings
by who can fix them. Scoring itself currently treats all sources the
same; ESP-attributed findings already self-demote to INFO inside the
emitting check (see `hidden_css.py`, `invisible_chars.py`), so the
scorer needs no source-aware logic yet.

---

### Agent 2 — Copy generator

**Purpose:** write a newsletter email from a brief — 3 subject
variants, preview text, plain-text body, sign-off — and self-critique
it with the same rules the audit uses.

**Entry points:**

```bash
python3 scripts/copy_gen.py                                            # interactive form
python3 scripts/copy_gen.py --brief briefs/lambton_mills.md --sender info@iknowtoronto.com
```

**Inputs:**
- A brief (interactive prompts or a markdown file with `goal:`,
  `audience:`, `key_message:`, `cta:`, `length_hint:`,
  `friction_point:`, `framing:`, repeatable `fact:` lines).
- Sender email (used to pull past-send history → voice profile).

**Outputs:**
- Stdout: subjects, preview, body, sign-off, refine trail.
- `output/copy_<ts>.md` — full copy + refine trail.
- `voice_profiles/<domain>.json` — cached sender voice profile
  (regenerated when history grows by ≥3 rows).

**Data flow (`copy_gen/`):**

1. Parse brief.
2. SQLite query for sender's prior sends.
3. **Voice extraction** (`voice.py`, one cached LLM call): produces
   structured profile — niche, tone, hook style, CTA style,
   vocabulary quirks, avoided patterns, average word count, sample
   subjects.
4. **Niche routing** (`prompt.py`): voice profile's `niche` field
   loads an extra context pack if matched (currently
   `toronto_precon_voice.md`).
5. **Generate** (`generator.py`, one structured-output LLM call):
   system prompt = stacked context packs + banned-phrase shortlist +
   niche pack + voice bullets. Output = Pydantic `DraftCopy` with a
   `story_mode` field (`no_story` / `micro_story` / `full_story`)
   chosen consciously.
6. **Critic** (`critic.py`, deterministic rule gate): homoglyph +
   invisible chars (reused from audit), subject heuristics, spam
   triggers, compound-signal score, body length, link count,
   Google-Drive detection, body shouting, emoji count, sign-off
   sanity. Returns Findings.
7. **Refine** (`refine.py`, only if Round 1 had blocking findings):
   regenerate with findings fed back as "fix these, preserve intent."
   Max 2 rounds total.
8. **Post-process**: strip duplicate sign-off model put inside body.
9. Write file + stdout.

#### Story modes

- `no_story` — straight advisory; for announcements, data updates, RSVPs.
- `micro_story` — default; opens 1-2 sentences of concrete observation/scene, then pivots.
- `full_story` — full Normal → Explosion → New Normal arc; persona-establishing only.

#### Context packs

Seven markdown files in `copy_gen/context/`. Edit without touching
Python — generator picks up changes on next run.

| File | Controls |
| --- | --- |
| `story_decision.md` | When to use which story mode |
| `storytelling.md` | Story frameworks, 5-second moment, R.E.C.C.O.T., Dinner / But-Therefore / So What |
| `copywriting.md` | Specificity, relative pricing, single CTA, Halabi category-first frame, honest friction |
| `open_rate.md` | Subject / preview rules with measured effect sizes |
| `structural_rules.md` | Plain-text-only, ≤200 words, link budget = `max(2, words // 125)` (ratio-based, not a flat cap), `{first_name}` placeholder, sign-off, no Drive |
| `spam_triggers.md` | Real-estate banned-phrase blocklist by category |
| `niche/toronto_precon_voice.md` | Toronto pre-construction voice pack |

#### Shared rules with audit

The critic imports the same helpers as `audit/checks/copywriting.py`.
Generated copy cannot trip its own audit — same `spam_triggers.md`,
same subject heuristics, same compound-signal score, same caps.

---

## Architecture in one picture

```
┌──────── Agent 1: Audit ──────────────────────────────────────────┐
│                                                                  │
│  raw .eml ──▶ parse_eml ──▶ detect_mode (default TEST)          │
│                                  │                               │
│                                  ▼                               │
│                  cleanup (only if TEST):                         │
│                    strip test prefix / headers / sub merge tags  │
│                                  │                               │
│                                  ▼                               │
│  asyncio.gather(per-email checks on cleaned email)              │
│                              │                                   │
│                              ├──▶ drift checks (if history)      │
│                              │    use ORIGINAL headers           │
│                              ├──▶ domain-health probes (live DNS)│
│                              │    SPF/DMARC/DKIM/MTA-STS/TLSRPT/ │
│                              │    BIMI/RBL/DBL/SMTP/HTTPS        │
│                              ├──▶ unsub_live POST (opt-in)       │
│                              ▼                                   │
│                          score_findings ──▶ verdict              │
│                              │                                   │
│                              ▼                                   │
│                          humanize (1 LLM call) ──▶ markdown     │
│                              + ModeInfo + cleanup transparency   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘

┌──────── Agent 2: Copy generator ─────────────────────────────────┐
│                                                                  │
│  brief ──▶ voice profile (cached LLM) ──▶ generate (1 LLM call) │
│                                              │                   │
│                                              ▼                   │
│                                          critic (rule gate)      │
│                                              │                   │
│                              if blocking ◀──┤                   │
│                              findings:       │                   │
│                              refine (Round 2)│                   │
│                                              ▼                   │
│                                          DraftCopy ──▶ markdown  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

Both agents share the SQLite memory layer (`memory/store.py`,
`memory/derived.py`, `memory/analyzer.py`) and the rule library
(`audit/checks/`, `copy_gen/critic.py`).

---

## Web UI — next milestone (not yet built)

The audit + copy-gen engines are CLI today. Planned MVP wraps the
audit engine in a web app so non-technical users can run audits
without a terminal.

**Scope:**

- Google OAuth sign-in (reuses `gmail_ingest/auth.py` token flow,
  expanded scopes for full mailbox read).
- Drag-drop `.eml` upload OR connect Gmail → tool starts polling
  `youraddress+audit@gmail.com` automatically.
- Per-user dashboard: list past audits, score trend, sender-domain
  breakdown, GO / REVIEW / NO_GO badges.
- Per-audit page: rendered markdown report (mode info + findings +
  humanized advice + technical breakdown).

**Stack:** FastAPI + HTMX + Jinja2 + per-user SQLite. Single Docker
container. Deployed to Fly.io / Railway.

**NOT in MVP web scope:**

- ESP integration (Mailchimp / Kit / etc.) — engagement data deferred.
- Magic-link auth — Google OAuth only.
- Multi-tenant Postgres — per-user SQLite is fine until growth pushes it.
- Copy-gen UI — Agent 2 stays CLI-only for v1.

Future steps (after MVP ships): humanized report v2 with prioritized
mitigation steps, dedicated subject-line generator, ESP webhook
ingest for real engagement-aware drift, body rewrite mode. All in
`TODO.md`.

---

## Repository layout

```
audit/                       — Agent 1
├── runner.py                — orchestrator (CHECKS list, audit() entry)
├── parse.py                 — .eml → ParsedEmail
├── mode.py                  — test/production heuristic detector
├── cleanup.py               — strip test markers + sub merge tags
├── scoring.py               — group-capped additive composite + hard gates
├── severity.py              — Severity enum, score thresholds
├── humanize.py              — LLM rewrite + composer-UI fix chips
├── renderer.py              — markdown report
├── report.py                — Pydantic Finding + Report + ModeInfo
├── checks/                  — per-email checks (17 files incl. unsubscribe_live)
├── drift/                   — cross-email checks (D01, D03, D04, D08, D10, D11)
├── esp/                     — ESP detection (10 profiles + cascade detector)
└── domain_health/           — live DNS / SMTP / HTTP probes
    ├── runner.py
    ├── dns_client.py        — async DNS w/ caching
    └── checks/              — 10 probe modules (adds sender_dbl.py for sender-apex blacklist scan)

copy_gen/                    — Agent 2
├── generator.py             — main generate() entry
├── critic.py                — deterministic rule gate
├── refine.py                — round-2 regenerate w/ findings
├── voice.py                 — sender voice extraction (cached)
├── prompt.py                — system-prompt assembly
└── context/                 — 7 human-editable context packs

memory/
├── store.py                 — SQLite + fuzzy-match iteration collapse
├── derived.py               — 12 derived columns extracted at save time
└── analyzer.py              — history aggregations for drift

gmail_ingest/                — Gmail API polling
├── auth.py                  — OAuth + token.json
├── poller.py                — fetch_by_query, mark_read
└── bootstrap.py             — backfill historical campaigns

scripts/                     — CLI entry points
├── audit_one.py             — audit one .eml
├── gmail_poll.py            — Gmail-polling service
├── copy_gen.py              — copy-generator CLI
├── bootstrap.py             — historical-campaign backfill
├── backfill_derived.py      — re-derive 12 derived columns
└── full_pipeline.py         — STUB (Step 4, not implemented)

tests/                       — pytest smoke suite
docs/                        — STEP1_CHECKS, PIPELINE, BACKLOG, DEMO, drift research
briefs/                      — example briefs for copy-gen
voice_profiles/              — cached voice JSON per sender domain
output/                      — JSON audit dumps + generated copy
reports/                     — humanized markdown reports
audits.db                    — SQLite memory (raw email bytes + derived columns)
TODO.md                      — roadmap
```

---

## How to start

**One-time setup:**

```bash
pip install -e .
echo "OPENAI_API_KEY=sk-..." >> .env

# Optional: Gmail polling. Google Cloud → enable Gmail API →
# Desktop OAuth client → download credentials.json → save at root.
```

**Run the agents:**

```bash
# Audit a local .eml — auto-detect test vs production
python3 scripts/audit_one.py path/to/email.eml

# Force test mode (cleanup applied)
python3 scripts/audit_one.py path/to/email.eml --mode test

# Force production mode (no cleanup)
python3 scripts/audit_one.py path/to/email.eml --mode production

# Opt-in: actually POST the unsubscribe URL (RFC 8058 live verify)
# WARNING: may trigger a real unsubscribe on third-party lists.
python3 scripts/audit_one.py path/to/email.eml --probe-unsub

# Audit live test sends from Gmail (loop)
python3 scripts/gmail_poll.py

# Generate copy (interactive)
python3 scripts/copy_gen.py

# Generate copy (scripted)
python3 scripts/copy_gen.py --brief briefs/lambton_mills.md --sender info@iknowtoronto.com
```

**Reading output:**

- `reports/audit_<ts>.md` → "What to fix" = humanized advice;
  "Technical breakdown" = full PASS/FAIL rollcall.
- `output/copy_<ts>.md` → final copy + refine trail.

---

## What this tool does NOT do

These exclusions are deliberate. They keep the PoC focused.

- **No engagement-rate ingestion.** ESP open / click / reply /
  unsubscribe rates are not consumed. Voice profile is built from
  message *content* only.
- **No A/B test orchestration.** Generator emits 3 subject variants;
  doesn't track which got used or how it performed.
- **Live RFC 8058 POST verification is OPT-IN only.** Default audit
  checks `List-Unsubscribe-Post` *header presence*. Pass
  `--probe-unsub` to actually POST and verify 2xx (with one-redirect
  follow). Not on by default because the probe may trigger a real
  unsubscribe on third-party lists.
- **No Google Safe Browsing / Web Risk lookup.**
- **No SpamAssassin / Postmark SpamCheck integration.**
- **No HTML output.** Plain text only. ESP wraps the template HTML.
- **No multi-step tool-use chain / RAG / vector store.** Per-LLM-call
  pattern: one structured-output call. Critic is deterministic. Max
  2 refine rounds. Static context packs, no run-time retrieval.
- **No production infra.** SQLite single file, single user, Gmail
  OAuth polling (not a webhook). Fine for PoC, not built for scale.
- **No lead CRM / scoring / enrichment.** Roadmap (`TODO.md` Agents
  3–8); not shipped.

If you need any of these, check `TODO.md` or `docs/BACKLOG.md` first
to see if it's tracked, then open an issue or update the file.
