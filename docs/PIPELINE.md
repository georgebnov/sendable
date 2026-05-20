<!--
  PIPELINE.md — Runtime flow map with exact file pointers.
-->

# Runtime pipeline

Two flows. They share the check library; nothing else.

---

## Flow A — Audit (Gmail polling, live)

```
  ESP test send
        │
        ▼
  YOURADDRESS+audit@gmail.com       (plus-address trick — no domain needed)
        │
        ▼
  Gmail filter: "to: *+audit@…"  →  label: audit-pending
        │
        ▼
  scripts/gmail_poll.py  (loop, default 10s interval)
        │
        ├── get_service                         gmail_ingest/auth.py
        ├── ensure_labels("audit-pending",      gmail_ingest/poller.py
        │                  "audit-done")
        ├── fetch_pending → [(msg_id, raw)]     gmail_ingest/poller.py
        │                                         (messages.get format='raw' → base64url decoded)
        ▼
  ┌────────── for each (msg_id, raw) ──────────┐
  │                                            │
  │  parse_eml(raw)                             audit/parse.py
  │      │                                     │
  │      ▼                                     │
  │  asyncio.gather(                            audit/runner.py
  │     checks.auth.run,                        audit/checks/auth.py
  │     checks.size.run,                        audit/checks/size.py
  │     checks.hidden_css.run,                  audit/checks/hidden_css.py
  │     checks.invisible_chars.run,             audit/checks/invisible_chars.py
  │     checks.homoglyph.run,                   audit/checks/homoglyph.py
  │  )                                          │
  │     │                                       │
  │     ▼                                       │
  │  compute_score / verdict                    audit/severity.py
  │     │                                       │
  │     ▼                                       │
  │  Report (Pydantic)                          audit/report.py
  │     │                                       │
  │     ▼                                       │
  │  if history provided: run_drift(parsed, history)  audit/drift/runner.py
  │     │     6 cross-email checks (D01/D03/D04/D08/ │
  │     │     D10/D11), gated on cold_start_ok       │
  │     │     (default ≥3 rows; D10 requires ≥8).    │
  │     │     Drift findings merge into same Report. │
  │     ▼                                       │
  │  save_email(raw, parsed, score)             memory/store.py
  │     │    Three-layer decision:              │
  │     │    L1: sha256(raw) exists → DEDUPED   │
  │     │    L2: ESP campaign-id match on       │
  │     │        (sender, campaign_id) → UPDATE │
  │     │        (Feedback-ID / X-*-Campaign-*) │
  │     │    L3: 5-word-shingle Jaccard vs last │
  │     │        3 rows from same sender,       │
  │     │        threshold adaptive to each     │
  │     │        stored row's score → UPDATE    │
  │     │    else → INSERT                      │
  │     │                                       │
  │     ▼                                       │
  │  render_markdown → reports/*.md             audit/renderer.py
  │     │                                       │
  │  mark_read(msg_id)                          gmail_ingest/poller.py
  └─────────────────────────────────────────────┘
```

### Entry points

- Gmail loop: `scripts/gmail_poll.py` (Day 3, live)
- Offline one-shot (skip Gmail, feed a local .eml): `scripts/audit_one.py` (live)

### Step 2 — memory

- Raw email storage: `memory/store.py` (SQLite `emails` table, live). Schema columns: `id, received_at, from_addr, subject, preheader, body_plain, raw, sha256 (UNIQUE), score`.
- `save_email(raw, parsed, score=None)` is called *after* audit runs. Three decision layers:
  - **sha256 dedup** — exact bytes already stored → `deduped`.
  - **ESP campaign-id pre-filter** — pulls an identifier from `Feedback-ID` (RFC 5965), `X-Mailchimp-Campaign-ID`, `X-Campaign`, `X-Campaign-ID`, `X-Klaviyo-MessageID`, or `X-AC-Campaign-ID`. Same sender + same campaign-id → ground-truth iteration → `updated`.
  - **5-word-shingle Jaccard fallback** — compares the new email's `subject + body_plain` to the last 3 rows from the same sender. Each candidate's threshold is adaptive: `0.60 + (score/100) * 0.30`, clamped to `[0.60, 0.90]`. NULL score uses default `0.80`. Best match clearing its threshold → `updated`; otherwise → `inserted`.
  - See `ITERATION_MATCHING.md` for the design rationale and open questions.
- `save_email(raw, parsed)` without a score (the bootstrap path) skips fuzzy matching entirely — pure INSERT unless `sha256` collides. Historical bootstrap rows land with NULL score.
- Alignment analyzer (last N → LLM narrates drift): `memory/analyzer.py` (stub — Day 5).
- Audit rows are **not** persisted to SQLite separately. The markdown/JSON files in `reports/` and `output/` are the audit output; the `emails.score` column carries the score into future fuzzy-match decisions.

### Step 4 — LLM humanization (Day 4, not yet wired)

Inserts between `Report` and `render_markdown`: one structured call takes the deterministic `Report` + last N emails from `memory/store.recent_emails()` and returns a `HumanizedReport` with exec summary + top 3 fixes + per-finding prose. `render_markdown` then formats that. Deterministic fallback if the LLM call fails.

---

## Flow B — Copy generator (Day 6, stubs only)

Self-Refine with a **deterministic** critic (reuses audit checks). No LLM critic. 2-iteration cap.

```
  brief
    │
    ▼
  generator (OpenAI gpt-4o-mini → subject / preview / body)    copy_gen/generator.py
    │
    ▼
  critic (runs audit.checks on the body)                        copy_gen/critic.py
    │
    ▼
  refine if score < threshold, else finalize (loop max 2)       copy_gen/refine.py
```

- CLI: `scripts/copy_gen.py` (stub)

## Flow C — Full pipeline (Day 7, stub)

Orchestrates B → human edits in ESP → test send → A → human iterates. Script stub: `scripts/full_pipeline.py`.

---

## Flow D — Bootstrap (seed `emails` table from Gmail history)

One-time sweep to seed the `emails` table with historical campaigns so drift detection has a baseline. User tags campaigns in Gmail with a label, bootstrap queries that label via the Gmail API and saves each raw message via `save_email`.

```
  python scripts/bootstrap.py --label AuditBootstrap
         │
         ▼
  get_service / get_user_email               gmail_ingest/auth.py
         │
         ▼
  resolve_query(label, query) → "label:AuditBootstrap"   gmail_ingest/bootstrap.py
         │
         ▼
  list_matching_threads (paginated, capped)  gmail_ingest/bootstrap.py
         │                                    (aborts if > max_count=500)
         │  returns: {threadId: [msg_id, ...]} newest-first per thread
         ▼
  confirm: "Found N threads. Import the latest bulk message from each? [Y/n]"
         │
         ▼  ┌── for each thread ──────────────────────────────────────────┐
            │  iterate msg_ids newest-first:                              │
            │    _fetch_raw(msg_id)           gmail_ingest/bootstrap.py   │
            │    parse_eml(raw)               audit/parse.py              │
            │    if List-Unsubscribe present → keep, stop walking thread  │
            │  save_email(raw, parsed)        memory/store.py (sha256)    │
            │  else thread has no bulk message → filtered                 │
            └─────────────────────────────────────────────────────────────┘
         │
         ▼
  Print "Saved N threads, deduped M, filtered K with no bulk."
```

One row per thread. Per-thread rule picks the real campaign over a prior test send (both are bulk, take the newer) and picks a campaign over a subscriber reply that Gmail threaded in (reply lacks `List-Unsubscribe`). `gmail_poll.py` on empty-DB startup invokes `bootstrap_interactive` inline after prompting `Bootstrap from Gmail now? [Y/n]`. No audits run during bootstrap — only raw + metadata are saved.

---

## Output artifacts (Flow A)

- `reports/audit_<ts>.md` — markdown report (the thing you read).
- `output/audit_<ts>.json` — full Report as JSON (mostly for debugging).
- `audits.db` — SQLite row per ingested email in the `emails` table (powers Step 2; filename is legacy).
- stderr — human-readable summary (audit_one.py only).

## Secrets / config (gitignored)

- `credentials.json` — Google OAuth client (Desktop app). Download once.
- `token.json` — auto-written on first `gmail_poll.py` run.
- `.env` — `OPENAI_API_KEY` for Day 4/6 LLM calls.

## Deferred (see BACKLOG.md)

- CloudMailin / SES inbound — post-PoC scaling path.
- 20 more checks to ship after the 5 live ones (Phase 1b).
- SpamAssassin via aiospamc + Docker.
- DNSBL / SURBL / URIBL / Safe Browsing.
- Live RFC 8058 one-click POST test.
- LLM humanization (Day 4).
- Alignment analyzer (Day 5).
- Copy generator (Day 6).
