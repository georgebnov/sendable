# Demo Prep — 3-hour window

Meeting in 3 hours. This doc: project map → exact commands → pre-flight.
You built it; this just gives you the words.

---

## 1. Project map

### What's here (one sentence each)

**Root / docs**
- `pyproject.toml` — dependency list; `pydantic`, `beautifulsoup4`, `lxml`, `confusable-homoglyphs`, Google API libs, `openai`, `python-dotenv`.
- `README.md` — quickstart.
- `AGENTS.md` — architecture (the doc your partner will read after demo).
- `TODO.md` — roadmap of what comes next.
- `PIPELINE.md`, `docs/BACKLOG.md`, `docs/STEP1_CHECKS.md`, `docs/STEP3_DRIFT_*.md` — research + deferred-feature tracking.

**`audit/` — Agent 1 (the auditor)**
- `audit/parse.py` — raw `.eml` bytes → `ParsedEmail` dataclass.
- `audit/report.py` — Pydantic shapes: `Finding`, `Report`, `HumanizedReport`.
- `audit/severity.py` — CRITICAL/HIGH/MEDIUM/LOW/INFO enum + scoring formula + GO/REVIEW/NO_GO rule.
- `audit/runner.py` — fans checks out via `asyncio.gather`; orchestrator.
- `audit/renderer.py` — builds the markdown report (Summary / What to fix / Technical breakdown).
- `audit/humanize.py` — one OpenAI call translating failing findings to marketer-prose; computes deterministic location citations.
- `audit/checks/auth.py` — SPF/DKIM/DMARC from Authentication-Results header.
- `audit/checks/size.py` — HTML byte size + presence.
- `audit/checks/hidden_css.py` — hidden-text salting (CSS selector resolution).
- `audit/checks/invisible_chars.py` — zero-width + bidi-override scanner.
- `audit/checks/homoglyph.py` — Cyrillic/Greek look-alikes in subject/body/link hostnames.
- `audit/checks/unsubscribe.py` — RFC 2369/8058 headers + visible link + Gmail-clip risk.
- `audit/checks/body_composition.py` — plain-text alt + image/text ratio.
- `audit/checks/link_quality.py` — shortener + anchor/href mismatch.
- `audit/checks/observability.py` — Feedback-ID presence.
- `audit/checks/copywriting.py` — reuses `copy_gen/critic.py` helpers on inbound emails with `copywriting.*` prefix.
- `audit/drift/runner.py` + `audit/drift/d01…d11.py` — 6 cross-email drift checks (DMARC regression, SPF/DKIM flip, policy downgrade, list-unsub regression, display-name rotation, Reply-To divergence).

**`copy_gen/` — Agent 2 (the writer)**
- `copy_gen/voice.py` — one LLM call over sender history → `VoiceProfile`, cached at `voice_profiles/{domain}.json`.
- `copy_gen/prompt.py` — splices context packs + voice profile + critic feedback into generator system prompt.
- `copy_gen/generator.py` — one structured-output call producing `DraftCopy`; derives first-person voice directive from sign-off; post-processes to strip duplicate sign-off.
- `copy_gen/critic.py` — deterministic rule gate (subject heuristics + spam triggers + compound-signal score + length + links + Drive detection + shouting + emoji + signoff + newsletter-word).
- `copy_gen/refine.py` — 2-round Self-Refine loop.
- `copy_gen/context/story_decision.md` — when to use no_story / micro_story / full_story.
- `copy_gen/context/storytelling.md` — story frameworks + R.E.C.C.O.T. + quality tests.
- `copy_gen/context/copywriting.md` — specificity, relative pricing, single CTA, Halabi frame, honest friction, anti-vocabulary.
- `copy_gen/context/open_rate.md` — subject/preview rules with measured lifts.
- `copy_gen/context/structural_rules.md` — plain-text, ≤200 words, ≤2 links, `{first_name}` merge tag, first-person voice rule, sign-off shape, no Google Drive.
- `copy_gen/context/spam_triggers.md` — real-estate banned-phrase blocklist by category.
- `copy_gen/context/niche/toronto_precon_voice.md` — Toronto pre-con voice pack.

**`memory/` — SQLite storage**
- `memory/store.py` — `emails` table, 3-layer iteration-collapse (sha256 → campaign-id → 5-word-shingle Jaccard); `history_for()` + `cold_start_ok()`.
- `memory/derived.py` — extracts 12 derived columns (from_domain, display_name, auth results, list-unsub flags) so drift checks don't re-parse.
- `memory/analyzer.py` — stub for future cross-email analysis.

**`gmail_ingest/` — Gmail polling**
- `gmail_ingest/auth.py` — OAuth flow (`credentials.json` → `token.json`), service builder, user-email lookup, `name+audit@domain` alias synthesis.
- `gmail_ingest/poller.py` — Gmail API query + mark-read.
- `gmail_ingest/bootstrap.py` — one-shot historical import by label.

**`scripts/` — entry points**
- `scripts/audit_one.py` — **Agent 1 CLI** (parse → audit → save → humanize → write markdown).
- `scripts/copy_gen.py` — **Agent 2 CLI** (brief file or interactive prompts → history → voice → refine → output).
- `scripts/gmail_poll.py` — wraps Agent 1 in a 10s polling loop + first-launch OAuth + first-run bootstrap prompt.
- `scripts/bootstrap.py` — Gmail label → DB (one-shot).
- `scripts/backfill_derived.py` — idempotent derived-column refill for legacy rows.
- `scripts/full_pipeline.py` — Day 7 orchestrator stub (not wired).
- `scripts/run_agent.py` — legacy.

**`tests/`**
- `tests/fixtures/samples/adversarial.eml` — hidden-CSS + invisible-char fixture (clean subject).
- `tests/fixtures/samples/gold_standard_hubspot.eml` — clean HubSpot newsletter.
- `tests/test_smoke.py` — basic smoke test.

**`briefs/`**
- `briefs/lambton_mills.md` — sample pre-con brief (real estate demo).
- `briefs/nab_avateq.md` — NAB Show Avateq brief (what you'll use in demo).

### Data flow

**AUDIT** (`python3 scripts/audit_one.py path/to.eml`):

```
.eml bytes
  → parse_eml()                       [audit/parse.py]
  → extract_all(parsed)               [memory/derived.py]
  → history_for(sender_domain)        [memory/store.py]
  → audit(parsed, history=...)        [audit/runner.py]
      ├── 15 content checks in parallel
      └── 6 drift checks (only if ≥3 history rows)
  → humanize(report, parsed)          [audit/humanize.py]   ← one OpenAI call
  → save_email(raw, parsed, score)    [memory/store.py]
  → render_markdown(report, humanized)
  → writes reports/audit_<ts>.md + output/audit_<ts>.json
```

**COPY GENERATION** (`python3 scripts/copy_gen.py --brief … --sender …`):

```
brief (file or interactive)
  → Brief Pydantic
  → history_for(sender_domain)        [memory/store.py]
  → extract_voice(history, domain)    [copy_gen/voice.py]  ← one OpenAI call (cached)
      ├── caches to voice_profiles/<domain>.json
      └── returns None if <3 history rows → "generic craft mode"
  → refine(brief, voice)              [copy_gen/refine.py]
      Round 1:
        generate(brief, voice)        [copy_gen/generator.py]  ← one OpenAI call
          ↳ build_system_prompt       [copy_gen/prompt.py]
          ↳ _derive_voice_directive   (injects "we/our" vs "I/my" based on sign-off)
        criticise(draft, brief)       [copy_gen/critic.py]
      If CRITICAL/HIGH fired:
      Round 2:
        generate(brief, voice, findings=round1)
        criticise(draft)
  → writes output/copy_<ts>.md
```

**Shared ground:** `audit/checks/copywriting.py` imports `copy_gen/critic.py` helpers. Generated copy cannot trip its own audit (moat #4).

---

## 2. Entry point — exact commands

### Env setup (one time this session)

```bash
cd /Users/george/GitHub/RealEstateEmilProject
source .pocEmail/bin/activate
grep OPENAI .env          # confirm key present — expect 1 line
ls credentials.json       # Gmail OAuth client creds
```

### Fresh-state reset before demo

```bash
# Clear run artifacts so live outputs are obviously new
rm -rf output/* reports/* voice_profiles/*

# Confirm DB has history (expect "avateq.com|17" or similar)
sqlite3 audits.db "SELECT from_domain, count(*) FROM emails GROUP BY from_domain;"
```

**Do NOT** delete `audits.db` or `token.json` unless you want to demo the full ingestion + OAuth flows from scratch (costs 15–30 sec mid-demo + risks OAuth consent-screen flake).

### Demo commands in order

**Step A — Gmail auth + ingestion** (open file only unless specifically demoing)

```bash
# If demoing live:
python3 scripts/gmail_poll.py
# Ctrl-C after a few polls — don't leave running during demo
```

**Step B — Audit a clean email**

```bash
python3 scripts/audit_one.py tests/fixtures/samples/gold_standard_hubspot.eml
```

Score 85+, verdict GO.

**Step C — Audit a bad email**

```bash
python3 scripts/audit_one.py tests/fixtures/samples/adversarial.eml
```

Score low, verdict NO_GO, multiple CRITICAL/HIGH findings. If `/tmp/emil_lambton_promo.eml` still exists, use it instead — it shows a real promotional email flagged.

**Step D — Generate a new email from the NAB brief**

```bash
python3 scripts/copy_gen.py --brief briefs/nab_avateq.md --sender info@avateq.com
```

This is the big one. `info@avateq.com` matches the 17 rows in DB → voice profile extraction fires live (visible as OpenAI call delay) → generator uses Avateq's actual voice → sign-off overridden to "Avateq Team" → first-person directive kicks in → body uses `we/our` not `I/my`.

Inspect the generated voice:

```bash
cat voice_profiles/avateq.com.json | python3 -m json.tool
```

**Step E (optional closer) — show the source**

Open `AGENTS.md` → point at the "does NOT do" section.
Open `copy_gen/context/spam_triggers.md` → "human-editable, no code change needed."

---

## 3. Pre-flight check

Run this sequence RIGHT NOW (all five should succeed):

```bash
cd /Users/george/GitHub/RealEstateEmilProject
source .pocEmail/bin/activate

# 1. Deps
python3 -c "import pydantic, bs4, openai, dotenv, googleapiclient; print('ok')"
# expect: ok

# 2. API key
grep OPENAI .env
# expect: OPENAI_API_KEY=sk-...

# 3. DB history
sqlite3 audits.db "SELECT from_domain, count(*) FROM emails GROUP BY from_domain;"
# expect at least one row with count >=3 (voice profile needs that)

# 4. Audit smoke
python3 scripts/audit_one.py tests/fixtures/samples/gold_standard_hubspot.eml 2>&1 | tail -3
# expect: JSON / Markdown / audits.db lines

# 5. Copy-gen smoke
python3 scripts/copy_gen.py --brief briefs/nab_avateq.md --sender info@avateq.com 2>&1 | tail -5
# expect: final body + sign-off + Written: ... line

# 6. Final clean for fresh demo artifacts
rm -rf output/* reports/* voice_profiles/*
```

If all 5 succeed — **you are demo-ready**.

### Things that could break live

1. **Network / OpenAI outage.**
   Both agents depend on `api.openai.com`. Audit: degrades to "Summary unavailable — technical breakdown only." Copy-gen: returns None + exits. **Mitigation:** if your internet flakes on stage, switch to showing a pre-generated report file from `reports/` that you ran earlier.

2. **`pip install -e .` will fail** (already seen) — setuptools is confused by `output/`, `briefs/`, `reports/`, `voice_profiles/` as auto-discovered packages. **Don't run it.** Your scripts already do `sys.path.insert(ROOT)`. Direct `pip install <pkg list>` is the workaround if a dep is missing.

3. **Wrong `--sender` = generic-craft mode.**
   Voice profile matches on `from_domain`. `info@avateq.com` → works (17 rows). `info@iknowtoronto.com` → no history → "generic craft mode (no profile)." Use matching sender for the voice-profile demo moment.

4. **Interactive prompts block on stdin.**
   `python3 scripts/copy_gen.py` with no args prompts for every field. If screen-sharing, prefer `--brief briefs/nab_avateq.md`.

5. **`token.json` expires.**
   Google OAuth tokens last 7 days without refresh. If you see auth errors from `gmail_poll.py`, delete `token.json` + re-run + approve consent screen. Don't do this mid-demo — pre-refresh now:

   ```bash
   python3 -c "from gmail_ingest.auth import get_service, get_user_email; s=get_service(); print(get_user_email(s))"
   # should print your email — if it prompts for OAuth, approve now not during demo
   ```

6. **Voice profile cache staleness.**
   Cache regenerates only when history grows by ≥3 rows. If you already ran copy-gen today, the `voice_profiles/avateq.com.json` file exists and the demo skips the LLM call (shows "cache hit"). **For impact:** wipe the cache before demo:

   ```bash
   rm -rf voice_profiles/*
   ```

7. **SQLite lock.**
   If `gmail_poll.py` is running in another terminal, `audit_one.py` may block. **Mitigation:** Ctrl-C the poller before running other commands.

8. **`/tmp/emil_lambton_promo.eml` may have been cleared** if your Mac cleaned `/tmp`. Check:

   ```bash
   ls -la /tmp/emil_lambton_promo.eml 2>/dev/null || echo "missing — use adversarial.eml instead"
   ```

9. **Zero hardcoded absolute paths** in the code. Everything uses `ROOT = Path(__file__).resolve().parent.parent`. You can `cd` anywhere.

10. **Terminal rendering.** The reports use emoji fix chips (✏️ 🛠️ 🌐). Verify your terminal font renders them — if not, pre-open a report in your editor instead.

### Fallback lines if something fails live

| Situation | What you say |
| --- | --- |
| OpenAI errors | "The LLM layer fails gracefully — the deterministic audit still runs; we just lose the marketer-facing summary. In production we'd have a cached fallback." |
| Voice profile None | "No history for this sender yet. The system knows to fall back to generic craft mode without faking personalization — better to say 'no voice yet' than pretend we know them." |
| Interactive stalling | "Let me switch to the scripted version." Ctrl-C, run `--brief` form. |
| OAuth consent fires | "First-run OAuth. Google Cloud Desktop credentials. One-time approval, then `token.json` caches everything." |
| Something truly hangs | Ctrl-C, open a pre-generated `reports/audit_*.md` from a past run, walk the structure. |

---

## 4. Demo script (5 minutes)

### Intro (30 sec, before terminal share)

> "Two agents. One audits inbound emails — deliverability plus copywriting. One writes new emails from a brief. Both share the same rule set, so the writer can't ship something the auditor would reject. Everything runs locally — SQLite memory, one OpenAI call per decision, deterministic critic in between."

### Step 1 — Audit a clean email (60 sec)

```bash
python3 scripts/audit_one.py tests/fixtures/samples/gold_standard_hubspot.eml
```

> "Runs 15 checks in parallel — auth, content, size, copywriting. Pulls sender history from SQLite, runs 6 drift checks. Scores, then one OpenAI call translates the findings into marketer-friendly advice with fix chips — pencil means the user can edit directly, wrench means the email tool does it, globe means DNS."

Open the resulting `reports/audit_<ts>.md` in your editor. Point at Summary → What to fix → Technical breakdown.

### Step 2 — Audit a bad email (60 sec)

```bash
python3 scripts/audit_one.py tests/fixtures/samples/adversarial.eml
```

> "Same tool on a bad email. Hidden CSS salting, invisible characters, homoglyphs — the adversarial patterns most audits miss. Score drops. But notice the advice — every item tells the marketer what to do in their composer, no jargon, no 'contact your developer'."

### Step 3 — Generate the NAB email (90 sec)

```bash
rm -rf voice_profiles/*
python3 scripts/copy_gen.py --brief briefs/nab_avateq.md --sender info@avateq.com
```

> "Brief file declares the goal, audience, key message, friction point, and supporting facts. The generator is explicitly instructed not to invent numbers — everything concrete traces to the brief.
>
> First it pulls Avateq's past 17 sends from memory and extracts a voice profile — niche, tone, hook style, vocabulary quirks — one OpenAI call, cached.
>
> Then one structured-output call produces three subject variants plus preview, body, sign-off, and a story mode choice. A deterministic critic runs the same rule set the audit uses. If anything CRITICAL or HIGH fires, one refine round regenerates with the findings fed back. Max two rounds."

Show the voice profile:

```bash
cat voice_profiles/avateq.com.json | python3 -m json.tool
```

> "This is what the system learned about Avateq just from reading past sends. Every future email for this sender uses this profile."

Open `output/copy_<ts>.md`. Point at:
- Three sentence-case subjects ≤50 chars.
- `{first_name}` merge placeholder (explain: "user swaps for their ESP's syntax — I have a table in the docs").
- Story mode field ("announcement mode here — no scene, straight advisory").
- Body uses "we/our" — "derived from the team sign-off automatically."
- Reply-ask CTA — "research says reply-asks get 2× more responses and train Gmail this is a real conversation."
- Refine trail at bottom — "proof the critic ran."

### Step 4 — Show the source, close (30 sec)

Open `copy_gen/context/spam_triggers.md`.

> "Seven human-editable markdown files drive the writer. Anyone on the team edits these — no Python. Add a phrase to the banned list, the generator picks it up on next run."

Open `AGENTS.md` → "What these agents do NOT do" section.

> "Deliberately scoped. No web research, no RAG, no multi-agent chains. One LLM call plus a rule gate plus a bounded refine loop. That's the whole architecture. Next step — and this is where lead qualification comes in — is Agent 3, the lead enrichment agent. Every email we touch generates signal we can feed into scoring. That's in `TODO.md`."

---

## 5. One-shot pre-meeting warmup

Run this block RIGHT NOW:

```bash
cd /Users/george/GitHub/RealEstateEmilProject
source .pocEmail/bin/activate
grep OPENAI .env && ls credentials.json token.json
sqlite3 audits.db "SELECT from_domain, count(*) FROM emails GROUP BY from_domain;"
python3 scripts/audit_one.py tests/fixtures/samples/gold_standard_hubspot.eml 2>&1 | tail -3
python3 scripts/copy_gen.py --brief briefs/nab_avateq.md --sender info@avateq.com 2>&1 | tail -5
rm -rf output/* reports/* voice_profiles/*
rm audits.db token.json
echo "READY"
```

If the final word printed is `READY` and no tracebacks showed — you're good. Close this terminal, open a clean one for the demo.
