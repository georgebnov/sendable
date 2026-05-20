# Step 3 — Drift Roadmap

*Single-file view of what's shipped, what's deferred, what was deliberately dropped, and what to explore next. Sourced from the consultant research at `STEP3_DRIFT_RESEARCH.md` and the Phase 0 + Phase 1 implementation in `audit/drift/`. Plain-English, implementation-oriented. 2026-04-21.*

---

## Shipped (Phase 0 + Phase 1)

See `STEP1_CHECKS.md` §13 for the decision-tree level specs.

**Foundation (Phase 0):**
- 12 derived columns added to `emails`: `from_domain`, `from_local`, `display_name`, `reply_to_domain`, `num_images`, `spf_result`, `dkim_result`, `dmarc_result`, `dmarc_policy`, `list_unsub_has_mailto`, `list_unsub_has_https`, `list_unsub_has_oneclick_post`. Populated automatically by `memory/derived.py:extract_all()` on every `save_email` call (bootstrap + poller + audit_one all share the same path).
- `memory/store.py:history_for(sender_domain, window_days, n_limit, exclude_sha256)` — returns full-row history, newest-first.
- `memory/store.py:cold_start_ok(history, min_rows=3)` — drift gate, row-count-only. Original research floor was `min_rows=10, min_age_days=21`; both were relaxed because the age gate was measured against `received_at` (ingest time, not send date) and tripped incorrectly on bootstrap-ingested historical data, and the row floor was too strict for low-cadence senders.
- `audit/drift/runner.py:run_drift(email, history)` — fans out Phase 1 checks via `asyncio.gather`. Wired into `audit/runner.py:audit()` via optional `history=` parameter.
- `scripts/backfill_derived.py` — one-shot re-parse of existing rows to populate derived columns.

**Phase 1 checks** (6 modules under `audit/drift/`):
- `d01_dmarc_regression` — DMARC fail on a historically-passing sender
- `d03_auth_flip` — SPF / DKIM pass-to-fail
- `d04_dmarc_policy_downgrade` — `p=` rank regression
- `d08_list_unsub_regression` — RFC 8058 compliance loss
- `d10_display_name_rotation` — identity drift + friendly-from spoof (spoof detection fires even without history)
- `d11_reply_to_divergence` — Reply-To drift, bulk-only, freemail-escalated

**Coverage**: auth integrity, RFC 8058 compliance, identity rotation. Enough for a PoC demo; Phase 2 adds breadth but not qualitative change.

---

## Phase 2 — six more ship-now checks

Each check needs new schema columns (listed per check) plus a new module under `audit/drift/`. All share the existing `cold_start_ok` gate (min_rows=3, min_age_days=14) unless noted otherwise.

### D02 — DKIM d= domain shift without overlap

**What it detects:** sender's DKIM signing domain changed to a value not seen before, without a dual-signing overlap period. A legit ESP migration runs both old and new keys for 7–30 days (M3AAWG best practice); bypassing the overlap means either a rushed cutover or compromise.

**New columns needed:**
- `dkim_d` TEXT — first DKIM-Signature header's `d=` value
- `dkim_s` TEXT — first DKIM-Signature header's `s=` (selector) value

**Decision tree:**
```
cold-start gate (min_rows=5)
S = distinct dkim_d values seen in prior 30 days
if current dkim_d ∉ S AND |S| ≥ 1:
    check the immediate prior message — did it dual-sign
      (contain both the old and new dkim_d)?
    ├── yes → MEDIUM (clean rotation in progress)
    └── no  → HIGH (hard cutover without overlap)
else → INFO pass
```

**Window:** 30 days. **Min rows:** 5.

### D05 — Received IP escape from /24 baseline

**What it detects:** top external `Received:` IP fell outside the historical /24 (IPv4) or /48 (IPv6) range for this sender. ESP migration (new /24 with coherent SPF) looks different from compromise (new /24 from residential / VPS space with SPF break).

**New columns needed:**
- `received_ip_external` TEXT — top external IP from `Received:` chain (walk inward from the trusted-boundary MTA)

**Decision tree:**
```
cold-start gate (min_rows=5, window 60 days)
S = set of /24-truncated IPs from prior 60 days
if current /24 ∉ S AND |S| ≥ 3:
    if current spf_result != 'pass' → HIGH
    else → MEDIUM
else → INFO pass
```

**Window:** 60 days. **Min rows:** 5.

### D06 — ESP fingerprint tuple inconsistency

**What it detects:** the 4-tuple `{return_path_domain, feedback_id_esp_tag, message_id_host, list_unsub_url_domain}` no longer agrees on a single ESP. Migration flips all four together; compromise via unauthorized relay breaks the tuple.

**New columns needed:**
- `return_path_domain` TEXT — registrable domain from `Return-Path:`
- `feedback_id_esp_tag` TEXT — last colon-segment of `Feedback-ID` (stable ESP identifier per RFC 5965)
- `message_id_host` TEXT — eTLD+1 of the `Message-ID` host part
- `list_unsub_url_domain` TEXT — eTLD+1 of the https URL inside `List-Unsubscribe`
- `esp_fingerprint` TEXT — inferred ESP name from the tuple majority (`mailchimp` / `sendgrid` / `kit` / `raw` / etc.)

**Decision tree:**
```
cold-start gate (min_rows=10)
tuple = {return_path_domain, feedback_id_esp_tag, message_id_host, list_unsub_url_domain}
reduce each to eTLD+1; compute majority ESP across the tuple
match_count = number of elements agreeing with the majority

if match_count == 4 → INFO pass
elif match_count == 3 → MEDIUM (1 disagrees — often benign ESP sub-branding)
elif match_count == 2 → HIGH (half the tuple disagrees)

additionally:
  inferred ESP vs majority ESP in last 10 history rows
  if different → HIGH (migration or relay takeover)
```

**Window:** last 10 messages. **Min rows:** 10. **Notes:** single most diagnostic multi-signal check in the research.

### D07 — Return-Path / envelope-from domain shift

**What it detects:** `Return-Path` domain changed to a previously-unseen value. Always co-fires with D02/D06 during legit migration; solo firing is suspicious.

**New columns needed:** `return_path_domain` (also used by D06 — so landing D06 and D07 together minimizes schema churn).

**Decision tree:**
```
cold-start gate (min_rows=5, window 60 days)
S = set of return_path_domain values from prior 60 days
if current ∉ S AND |S| ≥ 3:
    if D01, D02, or D03 co-fired on this message → HIGH
    else → MEDIUM
else → INFO pass
```

**Window:** 60 days. **Min rows:** 5.

### D09 — New link-destination Jaccard on eTLD+1 set

**What it detects:** a never-before-seen link destination appearing in the current message. Legit A/B tests introduce new click-tracking domains and keep them; compromise introduces one and reverts. Darktrace and Proofpoint identify new eTLD+1 as the strongest post-compromise content signal.

**New columns needed:**
- `link_domains_json` TEXT — JSON array of the full set of eTLD+1 hosts from every `<a href>` in the HTML

**Decision tree:**
```
cold-start gate (min_rows=5 with ≥1 link, window 60 days)
S = union of link_domains_json from prior 60 days
C = current message's link_domains set
new = C - S

# Exclude always-present "background" domains so we only flag novel destinations
new -= {from_domain, list_unsub_url_domain}

if |new| == 0 → INFO pass
elif |new| ≥ 1 AND |S| ≥ 10 → HIGH
elif |new| ≥ 1 AND 5 ≤ |S| < 10 → MEDIUM
else (|S| < 5) → INFO insufficient
```

**Window:** 60 days. **Min rows:** 5 messages containing ≥1 link.

### D12 — Send-cadence burst or silence

**What it detects:** the current send time falls far outside the sender's historical interval distribution. Validity explicitly documents "inconsistent volume" as penalized. Subtle: burst-then-silence vs silence-then-burst both matter.

**New columns needed:** none (uses existing `received_at`).

**Decision tree:**
```
cold-start gate (min_rows=15 — cadence statistics need larger sample)
Δi = intervals between consecutive received_at values over last 30 messages
median(Δ), MAD(Δ), p90(Δ), p99(daily_count), CV(Δ) computed

Δ_now = now - last_send time for this sender

if Δ_now > 3 × p90(Δ) AND next message arrives within 24h of current:
    → HIGH  (cadence-break-then-burst pattern)
elif last 24h contains ≥ p99(daily_count) + 1 messages from this sender:
    → MEDIUM  (burst)
elif Δ_now < 0.2 × median(Δ) AND historical CV(Δ) < 0.5:
    → MEDIUM  (too fast for a sender with previously-consistent cadence)
else → INFO pass
```

**Window:** 60 days for base statistics. **Min rows:** 15.

### Phase 2 — schema additions in total

Landing D02, D05, D06, D07, D09 at once would add these columns (D12 needs none):

```sql
ALTER TABLE emails ADD COLUMN dkim_d              TEXT;
ALTER TABLE emails ADD COLUMN dkim_s              TEXT;
ALTER TABLE emails ADD COLUMN received_ip_external TEXT;
ALTER TABLE emails ADD COLUMN return_path_domain  TEXT;
ALTER TABLE emails ADD COLUMN feedback_id_esp_tag TEXT;
ALTER TABLE emails ADD COLUMN message_id_host     TEXT;
ALTER TABLE emails ADD COLUMN list_unsub_url_domain TEXT;
ALTER TABLE emails ADD COLUMN esp_fingerprint     TEXT;
```

All populate from the already-stored `raw` bytes via additions to `memory/derived.py:extract_all()`. The backfill script picks them up with no changes.

### Phase 2 — ship order recommendation

1. **D07 + D06** together (they share `return_path_domain` + `feedback_id_esp_tag` + `message_id_host` + `list_unsub_url_domain`).
2. **D09** (its own `link_domains_json` column, broadest impact against VEC-style attacks).
3. **D02** (adds `dkim_d`, `dkim_s`; valuable during ESP migrations).
4. **D05** (IP escape — niche unless the user runs multi-ESP infrastructure).
5. **D12** (no schema change; depends on 15+ rows of history, so defer until enough baseline has accumulated).

---

## Phase 3 — multi-signal meta-classifier + positive drift

### 3.1 Meta-classifier

**What it does:** after Phase 1 and Phase 2 individual checks run, a meta-layer classifies the drift *pattern* across findings to distinguish legitimate evolution from compromise. The research identifies four archetypes:

- `REBRAND_OR_MIGRATION` — many infra signals moved together AND the pattern has held for ≥14 days AND content is largely stable
- `COMPROMISE_SHAPED` — a small number of infra signals moved AND the change is <7 days old AND content also shifted (D09 / D11 / D02 firing solo are strong indicators)
- `CONTENT_ONLY_DRIFT` — content signals moved without infra moving (possible ATO using the real ESP account)
- `AMBIGUOUS` — none of the above; report individual findings as-is

**New state required:** tracking when each "drift episode" started for a sender. The research suggests a new table or a computed field:

```sql
CREATE TABLE IF NOT EXISTS drift_episodes (
    sender_domain  TEXT NOT NULL,
    started_at     TEXT NOT NULL,
    last_seen_at   TEXT NOT NULL,
    fired_checks   TEXT NOT NULL,  -- JSON array
    classification TEXT             -- filled by meta-classifier when resolved
);
```

**Decision logic:**
```
after all Phase 1+2 checks run, collect:
  fired = findings with severity ≥ MEDIUM
  n_infra_fired    = count of fired in {D01, D02, D03, D04, D05, D06, D07}
  n_identity_fired = count of fired in {D10, D11}
  n_content_fired  = count of fired in {D09, D14, D15, D16, D17}
  persistence_days = days since the first of these checks first fired for this sender
                     (read from drift_episodes table)

IF n_infra_fired ≥ 3 AND persistence_days ≥ 14 AND n_content_fired ≤ 1:
    classify = REBRAND_OR_MIGRATION
    action   = suppress the individual findings, emit one INFO-level summary,
               and recalibrate baselines (treat new values as the new normal)
ELIF n_infra_fired in {1, 2} AND persistence_days < 7
     AND (D11 fired OR D09 fired OR D02 fired solo):
    classify = COMPROMISE_SHAPED
    action   = escalate each fired finding's severity by one level
ELIF n_content_fired ≥ 2 AND n_infra_fired == 0:
    classify = CONTENT_ONLY_DRIFT
    action   = emit a dedicated "possible account takeover via real ESP account"
               finding on top of the individual findings
ELSE:
    classify = AMBIGUOUS
    action   = no change; surface individual findings unchanged
```

**Known ceiling:** surgical thread-hijack VEC (attacker on a real account replies into an existing thread with new banking details) leaves every infra + content signal unchanged. Proofpoint reports mean VEC dwell time 233 days. This classifier won't catch that — document the limitation explicitly.

### 3.2 Positive-drift suppression

**What it does:** some drift transitions are improvements, not regressions. Flagging them as failures punishes the user for doing the right thing. Suppress the computed severity; log as `INFO: improving` instead.

**Transitions to invert** (each is a negative of a Phase 1/2 check):
- **DMARC policy upgrade** (rank `none → quarantine → reject`) — currently D04 stays silent on upgrades; formalize this as the positive path
- **Preheader appeared** where previously absent (currently no check fires on this; Phase 4's D17 inversion)
- **mailto-only → added https / one-click compliance** — D08 inverse: gaining RFC 8058 compliance instead of losing it
- **First appearance of `Feedback-ID`** — sender started emitting the ESP's campaign-feedback header
- **audit_score trending upward** — D18 (Phase 4) inverse

**Implementation pattern:**
```python
POSITIVE_TRANSITIONS = {
    "d04_dmarc_policy_downgrade": lambda prev, cur: policy_rank(cur) > policy_rank(prev),
    "d08_list_unsub_regression":  lambda prev, cur: cur_has_oneclick AND not prev_had_oneclick,
    # ...
}
POSITIVE_DRIFT_SUPPRESSION_WINDOW_DAYS = 30

# In each drift check's tail, before returning a Finding:
if check_name in POSITIVE_TRANSITIONS and POSITIVE_TRANSITIONS[check_name](history, current):
    return [Finding(severity=INFO, passed=True,
                    message=f"{check_name}: positive drift — {improvement_description}")]
```

**Baseline re-adoption:** after `POSITIVE_DRIFT_SUPPRESSION_WINDOW_DAYS` (default 30), the new improved state *becomes* the baseline. Regressing back to the old pre-improvement state now fires HIGH regardless of the original pre-improvement history.

---

## Phase 4 — ship-soon checks (D13–D19)

Narrower applicability, higher false-positive rates, or bigger schema/dep requirements. Land after Phase 2+3 are stable.

### D13 — Message-ID host drift
New column: `message_id_host` (already added by Phase 2 D06). Tree: prior 30-day set S of `message_id_host` eTLD+1; if current ∉ S AND D06 also fires → MEDIUM. Strong forensic precedent but many ESPs legitimately rotate Message-ID hosts (Mailchimp's `mcdlv.net` subdomains), so require co-firing with D06.

### D14 — Subject-style drift
No new columns (uses existing `subject`). Per-sender baseline: `len(subject)`, ALL-CAPS ratio, emoji count, `!`/`?` run-length. Mann–Whitney U (stdlib-only reimplementation or `scipy` dep — TBD) on last 10 vs prior 30 for each metric. Fire MEDIUM when ≥2 of the 4 metrics shift at p<0.05. **Min rows:** 20.

### D15 — Body-length distribution shift
New column: `body_plain_len` INTEGER (or compute on the fly from `body_plain`). Log-transform, Mann–Whitney on last 5 vs prior 20. MEDIUM on shift; LOW standalone.

### D16 — Language change
New column: `body_lang` TEXT. **Requires `langdetect` dep**. Skip for bodies with <20 tokens (unreliable). If current differs from sender's top-2 historical languages → MEDIUM; co-firing with D09 → HIGH.

### D17 — Preheader presence drop
No new columns (`has_preheader` can be `preheader IS NOT NULL` at query time). If last 10 had `preheader IS NOT NULL` ≥80% and current is NULL → LOW. Often benign template change; worth noting only as a compromised-generator hypothesis signal.

### D18 — Audit-score trendline
No new columns (uses existing `score`). Linear regression of score over last 10 messages against timestamp; fire MEDIUM when slope < −5 points/message AND R² > 0.5. Captures compounding degradation before any single check trips.

### D19 — Template-engine fingerprint change
New column: `esp_fingerprint` (already added by Phase 2 D06). Transition from a recognized ESP to `"raw"` (no recognized ESP headers) → HIGH. ESP-to-different-ESP → MEDIUM unless D06 already fires (D19 subsumed).

---

## Drop list — what we will NOT build

Each of these sounds useful and isn't. Keep them off the roadmap.

1. **Absolute subject-line thresholds** (length, specific "spam words"). RETVec-style LLM filters at Google / Microsoft / Yahoo killed keyword blacklists in 2023–2024 (`security.googleblog.com/2023/11`). Use relative drift (D14) if anything.
2. **Absolute image-to-text ratio as a drift alert.** Already covered for the current email in Step 1 (`content.image_text_ratio`); Email on Acid found 23 filters ignored ratio alone above 500 chars of body text, so cross-email drift on this metric adds no signal.
3. **Absolute link count.** Newsletters legitimately carry 20+ links; transactional mail carries 2–3. Use D09 relative drift, not absolute count.
4. **Typo detection in body text.** Modern filters tolerate typos; so do recipients. Wasted effort.
5. **BIMI / VMC lapse as a compromise signal.** Certificate expiry is almost always an ops hygiene failure, not attacker behavior. It affects inbox UX (missing logo / blue check) but not deliverability itself.
6. **MX-record change detection.** Not reliably extractable from a single inbound message's MIME. Defer entirely unless the project later ingests outbound DSNs (bounce notifications).

---

## Unknown unknowns — dimensions worth exploring in future iterations

Seven dimensions the research flagged as instrument-panel material for v2, with moderate precedent but not enough to make Phase 4:

1. **Message-ID structural signature drift** — not the host (that's D13), but the *shape* of the left-hand side: hex-vs-numeric-vs-mixed patterns; sequential numeric IDs are a documented automated-tooling tell.
2. **Tracking-pixel eTLD+1 drift** — the first `<img src>` host is typically stable per ESP; changes when the generator code path changes.
3. **UTM-parameter pattern drift** — `utm_source` / `utm_medium` / `utm_campaign` naming conventions are surprisingly stable per campaign generator.
4. **Charset / Content-Transfer-Encoding drift** — always `utf-8; quoted-printable` suddenly becoming `iso-8859-1; base64` is an inflection point.
5. **MIME boundary-string shape** — JavaMail vs Python `email.mime` vs Mailchimp vs Kit all emit distinctive boundary patterns; drift here indicates a different code path generated the message.
6. **Precedence / Auto-Submitted header presence drift** — bulk senders conventionally stamp one; appearance/disappearance indicates a different sending pipeline.
7. **Organizational DKIM alignment-level drift** — drift between `d=brand.com` and `d=mail.brand.com` changes who bears reputation. More sensitive than D02's strict-equality check.

None are mandatory for v1; each is a candidate for an "instrument panel" that surfaces curious deltas without blocking verdicts.

---

## Ship-order summary (if returning to drift later)

1. **Phase 2 batch A**: D06 + D07 (share 4 schema columns; together implement the most diagnostic tuple-consistency signal). ~4 new columns, ~2 check modules, ~300 lines.
2. **Phase 2 batch B**: D09 (link-domain Jaccard — broad anti-VEC coverage). 1 column, 1 module.
3. **Phase 2 batch C**: D02 (DKIM shift). 2 columns, 1 module. Good to pair with an ESP-migration demo.
4. **Phase 2 batch D**: D05 + D12. D05 is niche; D12 needs 15+ rows so realistically requires longer baseline.
5. **Phase 3**: meta-classifier + positive-drift suppression. Requires Phase 2 outcomes to be interesting. New `drift_episodes` table. ~200 lines including positive-drift inversions retrofitted into D04 and D08.
6. **Phase 4**: D13–D19 as opportunistic additions when their specific signals justify the code.

**PoC recommendation:** stop at end-of-Phase-1, move to LLM humanization (originally Day 4), then to copy generation (originally Day 6). Return to Phase 2+ only when drift coverage gaps are identified from real usage data, not anticipated.
