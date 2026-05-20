<!-- README.md — Project overview. Keep short. -->

# Email audit + copy generator

Pre-send audit for anyone who needs their emails to land in the inbox,
protect sender reputation, and actually get opened.

Local-first desktop app. Connects to Gmail, polls test sends to your
`+audit@` plus-address, audits each one, surfaces the report in a
local web UI.

- Single source of truth: [`AGENTS.md`](AGENTS.md)
- Runtime flow: [`docs/PIPELINE.md`](docs/PIPELINE.md)
- Deferred roadmap: [`docs/BACKLOG.md`](docs/BACKLOG.md)

## One-click run

```bash
pip install -e .
python3 app.py
```

App starts, browser opens to `http://127.0.0.1:8765/`, tray icon
appears (Quit from there). First run: follow the **Setup** link to
connect Google. Then click **Start polling** on the dashboard.

## Flow

1. Build an email in your ESP (Mailchimp, Klaviyo, ActiveCampaign, whatever).
2. Send the test to `YOURADDRESS+audit@gmail.com`.
3. Gmail filter labels it `audit-pending`.
4. `scripts/gmail_poll.py` polls every 10 s, pulls the raw MIME via Gmail API, saves the raw email to `audits.db` (`emails` table), runs 5 async checks, writes `reports/audit_<ts>.md`, marks the message read.
5. Open the markdown report, fix, send another test.

## Quick start

### 1. Install deps

```bash
pip install -e .
```

### 2. Gmail OAuth setup (one-time, ~20 min)

1. Google Cloud Console → create a project → enable Gmail API.
2. APIs & Services → Credentials → Create OAuth 2.0 Client ID → **Desktop app**.
3. Download the JSON, save as `credentials.json` at project root (it's gitignored).
4. In Gmail, create a filter: `to:(YOURADDRESS+audit@gmail.com)` → Apply label `audit-pending`.

### 3. First run

```bash
python scripts/gmail_poll.py
# Opens browser for consent. token.json is saved and reused thereafter.
```

### 4. Test the audit without Gmail (useful while setting up OAuth)

```bash
python scripts/audit_one.py tests/fixtures/samples/adversarial.eml
# -> output/audit_<ts>.json
# -> reports/audit_<ts>.md
# -> row in audits.db (emails table, raw bytes + metadata)
# -> human summary on stderr
```

### 5. Inspect stored emails

```bash
sqlite3 audits.db "SELECT id, received_at, from_addr, subject FROM emails ORDER BY id DESC LIMIT 10;"
```

### 6. Bootstrap historical emails (optional, for drift detection)

Drift detection needs ≥3 prior emails per sender to produce signal. If you have ESP campaigns sitting in your Gmail from before this tool existed, seed them in one pass:

1. In Gmail, create a label (e.g. `AuditBootstrap`).
2. Search for your historical campaigns (`from:hello@yourdomain.com`, `category:promotions`, whatever finds them), shift-select the matches, apply the label.
3. Run:
   ```bash
   python scripts/bootstrap.py --label AuditBootstrap
   ```

`gmail_poll.py` also offers to bootstrap interactively on its first launch when the DB is empty.

Bootstrap groups matches by Gmail thread and keeps the **latest bulk message** (has `List-Unsubscribe`) from each thread. If your thread has a test send + real campaign, you get the real one. If it has a campaign + a subscriber reply, you get the campaign. Threads with no bulk message at all (e.g., a pure personal-mail conversation that accidentally got the label) are skipped.

Prereq: you must be a recipient of those campaigns — they need to exist in your Gmail with original headers. Forwards don't work (headers get corrupted by the forwarder).

## What's live vs stubbed

- **Live**: 9 audit checks (auth / size / hidden-CSS / invisible-chars / homoglyph / unsubscribe / body-composition / link-quality / feedback-id), 6 drift checks (D01/D03/D04/D08/D10/D11), scoring, raw-email SQLite store with iteration-collapsing fuzzy match, Gmail bootstrap, markdown renderer, Gmail polling loop, LLM humanization, **copy generator (Day 6)**.
- **Stubbed**: full pipeline glue (Day 7). See `BACKLOG.md`.

## Copy generator quickstart (Day 6)

```bash
# 1. Put OPENAI_API_KEY in .env
echo "OPENAI_API_KEY=sk-..." >> .env

# 2. Write a brief
cat > briefs/lambton_mills.md <<'EOF'
goal: share context on the Lambton Mills release with past buyers
audience: past buyers in Toronto, mostly end-users with some investors
key_message: pricing landed at mid-$1,100s per sq ft, competitive for the corridor
cta: reply
length_hint: short
friction_point: deposit structure is heavier than usual at 20% over 18 months
framing: project
EOF

# 3. Generate
python scripts/copy_gen.py --brief briefs/lambton_mills.md --sender info@iknowtoronto.com
# → 3 subject variants + preview + body + sign-off on stdout
# → output/copy_<ts>.md with full refine trail
# → voice profile cached at voice_profiles/<domain>.json
```

Context packs under `copy_gen/context/` (storytelling, copywriting, open-rate,
structural rules, spam triggers, Toronto pre-con niche) are human-editable —
tune without code changes. Voice profile is extracted from the sender's past
emails in the `emails` table and describes their tone, niche, hook style,
vocabulary quirks, and typical body length; cached on disk and refreshed when
history grows by ≥ 3 rows.
