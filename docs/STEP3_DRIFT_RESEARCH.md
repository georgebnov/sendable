# Step 3 — Drift Detection: Research Brief

*What we need you (or your research assistant / LLM-search tool) to investigate before we plan implementation. Dated 2026-04-21. Bring findings back and we'll refine the plan for `memory/analyzer.py` and a new check module against the existing `emails` table.*

---

## 1. What we've built so far

The tool audits individual emails via 9 deterministic checks (see `STEP1_CHECKS.md`) and stores every ingested email in a single SQLite `emails` table. Per-row data we can compute against:

| Column | What it is |
| --- | --- |
| `received_at` | ISO timestamp of ingest |
| `from_addr` | full `From:` header string |
| `subject` | subject line |
| `preheader` | hidden preview-text element, or NULL |
| `body_plain` | text/plain MIME part |
| `raw` | full original bytes (so any header or DKIM signature is recoverable) |
| `sha256` | content hash |
| `score` | audit score 0–100 (NULL for bootstrapped historical rows) |
| `campaign_id` | ESP campaign identifier (Feedback-ID, X-Mailchimp-Campaign-ID, etc.) or NULL |

One row per campaign, approximately — the `save_email` three-layer match (sha256 → campaign-id → Jaccard fuzzy) collapses test iterations into a single row. See `ITERATION_MATCHING.md` for that logic.

---

## 2. What Step 3 is supposed to do

Given a new email from a known sender, compare it to that sender's prior rows and emit additional `Finding`s when something has drifted in a way that would hurt deliverability. Same shape as a check — `(ParsedEmail, history) → list[Finding]`. Slots into the existing audit pipeline right before `render_markdown` in `audit/runner.py`.

**The strategic question** the research should answer: which drift signals do the three-big-inbox-providers (Gmail, Yahoo, Microsoft) and large third-party filters (SpamAssassin, Barracuda, Proofpoint) actually track across time for a given sender, and which of those signals can we compute from the data we already store?

We're NOT trying to replicate full provider reputation systems (we don't have the data — see §6). We're trying to catch the drift patterns that providers *penalize* so the user can fix them before the next send gets throttled.

---

## 3. Core research questions

### 3.1 How do providers compute sender reputation over time?

- Gmail's sender reputation model — what signals feed it, how often is it updated, what's the decay window? Is it IP-based, domain-based, or blended?
- What specifically moves Google Postmaster Tools' reputation categories (Bad → Low → Medium → High)?
- Microsoft SNDS and Outlook reputation — same question.
- Yahoo Sender Hub — what does their reputation UI expose?
- Third-party reputation services (Return Path / Validity, Talos IP reputation, Cloudmark) — what do they publish about their drift-scoring methodology?

### 3.2 What specific drifts trigger actual deliverability consequences?

Rank these by how much providers appear to care. Which are documented, which are inferred from experiments, which are folk wisdom?

- **Authentication drift** — DKIM `d=` domain changes, SPF record updates, DMARC policy downgrades (`p=reject` → `p=none`), BIMI certificate lapses.
- **Infrastructure drift** — sending IP changes, sending subdomain changes, ESP migration (Mailchimp → Klaviyo → ActiveCampaign), new MX records.
- **Identity drift** — display-name rotation on the same sending address, From-address changes, Reply-To changes, Return-Path changes.
- **Volume drift** — sudden spike or drop in send volume, unusual send-time patterns, weekday vs weekend shifts.
- **Engagement drift** — falling open rates, falling click rates, rising unsubscribe rates, rising complaint rates, spam-folder placement rate creep.
- **List-hygiene drift** — rising bounce rates (especially hard bounces), sending to recycled/spamtrap addresses, sending to previously-unsubscribed users.
- **Content drift** — subject-line style changes, body-template changes, link-destination changes, preheader-presence changes, image-to-text-ratio changes, language changes.
- **Routing drift** — List-ID rotation, Feedback-ID pattern changes, X-Mailer / X-Campaign-ID shape changes.

For each: is the drift itself the signal, or is it the **rate** or **magnitude** of the drift? Do providers tolerate gradual change (slow brand evolution) but penalize sudden change (signs of compromise)?

### 3.3 What's the distinction between "evolving normally" and "compromised / going rogue"?

This is the interesting nuance. A legit brand refresh changes subject style, display name, and template — those same signals also describe a compromised account. How do providers tell them apart? Can we?

Likely lever: **which signals move together**. A legit rebrand changes display name + subject style + body template simultaneously and holds the new state. A compromised account changes one or two signals erratically (e.g., sudden display-name rotation within otherwise stable content).

### 3.4 Is drift ever "good"?

Some drifts are fixes: missing preheader → preheader added, score 40 → 90, DMARC policy hardened. We probably don't want to flag these as failures. Do provider models treat "improving" drift positively, or is any change treated as risk?

### 3.5 Time windows

Over what window do providers measure drift? 7 days, 30 days, 90 days? Does it vary by metric? (Engagement metrics are probably smoothed over weeks; auth changes can hit reputation within hours.)

What's the right window *for us*, given we'll typically have O(dozens) of historical rows per sender, not thousands?

---

## 4. Signals we could compute from our stored data

This is the actually-actionable list. Everything here is computable from the `emails` table alone, no external API. The research should tell us which of these map to a real provider concern vs. which are noise for us to drop.

| Candidate signal | What we'd compute | Why it might matter |
| --- | --- | --- |
| Display-name rotation | distinct display-name tokens in `from_addr` across last N rows for same address | providers penalize shared-inbox abuse, rotating-rep tools |
| Subject-style drift | average length / casing / emoji-density of last N subjects vs current | sudden "FLASH SALE" from a staid B2B sender is a signal |
| Preheader-presence rate | fraction of last N that had non-null preheader | regressing away from using preheader is a quality drop |
| DKIM signing-domain drift | `dkim-signature` header's `d=` value across history; any change? | ESP migration or spoofing attempt both look like this |
| ESP / `campaign_id` pattern change | distinct Feedback-ID prefixes across history | sender switched ESP — reputation has to rebuild |
| Auth-result regression | DMARC/SPF/DKIM flipping from pass to fail or missing | immediate deliverability risk |
| Audit-score trendline | linear regression over recent `score` values, flag downward slope | compound signal — catches multiple degradations |
| Body-length distribution shift | mean/stddev of `body_plain` length, flag 2-sigma outliers | campaign-format shift or template compromise |
| Subject-template uniformity | Jaccard across recent subjects; sudden drop = style change | same shape as our iteration-matching |
| Send-cadence drift | intervals between `received_at` values, flag anomalies | weekly → daily, or vice versa, both signal something |
| Link-destination registrable-domain rotation | set of eTLD+1 domains in `<a href>` across history | new tracking domain or new destination = new campaign infrastructure |

For each, two questions the research should help answer:
1. Does any real provider documented to use this?
2. How many rows (sample size) do we realistically need before this signal has meaning rather than noise?

---

## 5. Resources likely to have answers

Starting points for the researcher:

**Official provider documentation:**
- Gmail Postmaster Tools Help (`support.google.com/mail/answer/6227174`) — reputation categories, feedback loop
- Microsoft SNDS docs — data it exposes on IP reputation
- Yahoo Sender Hub — their public sender guidelines
- Apple iCloud postmaster guide (if exists)

**Open-source filter engines** (useful as a proxy for what providers weight):
- SpamAssassin rules repository — any time-series or reputation rules
- rspamd — its reputation module
- Mailu / Postal — deliverability heuristics

**Industry publications:**
- Word to the Wise blog (Laura Atkins) — deep technical content on sender reputation
- Email Geeks Slack (archive if accessible)
- Return Path / Validity whitepapers — methodology is sometimes published
- Suppressed or leaked: Gmail / Yahoo internal slides from conferences (M3AAWG, Litmus Live)

**Research papers:**
- ACM / IEEE papers on "sender reputation drift," "email reputation time series," "domain reputation decay"
- Any paper authored by researchers from Google / Microsoft / Proofpoint on their own reputation systems (rare but some exist)

**Tools already doing drift-ish work** (reverse-engineer their feature lists):
- GlockApps — reputation monitoring
- 250ok / Validity Everest
- MailMonitor
- ReputationMonitor
- DMARC Analyzer / Dmarcian

---

## 6. What the researcher should explicitly NOT waste time on

To keep scope focused:

- **IP reputation / DNSBL drift.** That's computed at the MTA level before the message even gets to a content filter. We don't have access to sending IPs in our stored data, and even if we did, the providers don't expose their IP-reputation scores. Out of scope.
- **ML / embedding-based drift detection.** The tool is deterministic; the LLM advisory pass (deferred) can summarize findings but never carry the verdict. Treat embedding-based drift as a non-option.
- **Engagement metrics** (open rate, click rate, bounce rate, complaint rate). These live in the ESP, not in our raw MIME. We can't compute them. The research should tell us whether any *content-side* signal correlates with engagement drift (so we can catch the correlate), but not "go find the engagement data."
- **Live blacklist lookups.** Tracked separately in BACKLOG (`dnspython` upgrade).
- **Full provider-grade reputation scoring.** We have dozens of emails per sender, not millions; any approach that assumes provider-scale data is wrong for us.

---

## 7. What we want from the researcher

A document (or detailed findings) that answers:

1. **The short list of drift signals that matter** — rank-ordered by how much they actually affect deliverability (with citations where possible — official docs, SpamAssassin rules, published experiments). Out of the candidate list in §4, which should we actually build? Which should we drop?
2. **The weights / severities** — is subject-style drift a higher-priority signal than preheader-presence rate, or vice versa? Which drifts should be CRITICAL vs HIGH vs MEDIUM in our audit output?
3. **Thresholds** — at what magnitude does each drift start to matter? ("Display-name rotation is a problem if distinct names exceed N in the last K sends" — what are N and K?)
4. **Time windows** — what's the right recency cutoff for drift analysis? Last 7 days? Last 20 sends? Rolling 30 days?
5. **Per-sender sample-size minimums** — how many prior rows do we need before a drift signal has meaning rather than noise?
6. **The normal-vs-compromised distinction** — any heuristics for telling "legitimate rebrand" from "account compromised or going rogue." Especially: which signal co-movements indicate normal evolution vs which indicate trouble?
7. **What providers actually ignore** — things we might assume matter that actually don't. Avoid over-engineering a signal that has no downstream impact.
8. **Blind spots** — what drift dimensions exist that we haven't thought to list in §4? Unknown unknowns are the most valuable thing a researcher can surface.

---

## 8. How this will feed back into planning

When the research comes back, we'll distill it into:

- A concrete list of drift checks to implement (with severities and thresholds).
- A schema decision: do we need any new columns in `emails`, or can everything be computed from what's already stored?
- A plan for `memory/analyzer.py` (currently a stub) — it becomes the drift-computation module, same shape as a check.
- An update to `STEP1_CHECKS.md` (renamed or expanded) with the new drift checks documented in the same plain-English style.
- A BACKLOG refresh moving "Cross-email: display-name drift" and the broader alignment analyzer items from Deferred to In-Progress.

The goal is to have enough concrete guidance that implementation is largely mechanical — the hard thinking is what the research is for.
