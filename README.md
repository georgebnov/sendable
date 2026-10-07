# Sendable

Find out why an email lands in spam, and fix the domain so it stops happening.
Runs on your machine. No account, no service, nothing uploaded.

Built to be used by an agent. Every command prints JSON, and `SKILL.md` is the
contract an agent reads to know when and how to run it.

## Install

There is no install step. You need [`uv`](https://docs.astral.sh/uv/), and the
scripts declare their own dependencies.

```bash
git clone https://github.com/georgebnov/sendable.git && cd sendable
uv run scripts/audit.py tests/fixtures/clean_bulk.eml --offline --pretty
```

The first run takes a few seconds while `uv` resolves and caches. Later runs take
0.1 seconds.

## The two things it does

**Grade one email.** Save a message as `.eml` and audit it.

```bash
uv run scripts/audit.py mail.eml
```

Over 100 checks: the copy and structure of the message, SPF, DKIM, DMARC and
whether they align, MTA-STS, TLSRPT and BIMI records, 32 blocklists, URL
reputation, a live SMTP probe, and 6 checks that compare this send against the
sender's earlier ones.

That last group is the reason reports are stored. "Your DMARC policy went from
reject to none" and "this display name has never appeared before" are statements
about a sequence. No amount of looking at one message produces them.

**Fix the domain.** Receiving providers mail you a daily XML report listing
everything that sent mail claiming to be your domain. Feed those in.

```bash
uv run scripts/dmarc.py ingest ~/Downloads/*.xml.gz
uv run scripts/dmarc.py status --domain example.com --pretty
```

`status` returns one next step. It will not tell you to tighten your DMARC policy
while a real sender of yours is failing alignment, because that would start
rejecting your own mail.

`SKILL.md` has the ten-minute setup: two plus-addresses on your own mailbox and
one DNS record.

## Where things go

```
.sendable/audits/     one JSON file per audited email
.sendable/dmarc/      one JSON file per aggregate report, grouped by domain
```

Plain JSON on disk, written once and never changed. The query these answer is "the
last 30 sends from this sender", so a database would add a schema and a binary
file and buy nothing at this size. Files also version in git, so you can diff your
own history, and one immutable file per record cannot be corrupted by two writers.

They hold real subject lines and link URLs. `.sendable/` is gitignored by default;
committing it is a deliberate choice.

## Optional

Set `OPENAI_API_KEY` to turn on the checks that ask a model to judge the copy.
Without it those report INFO and pass, and nothing else changes.

## Developing

```bash
just check     # lint, types, tests, coverage floor. What CI runs.
just coverage  # per-file coverage, worst first
just smoke     # run the packaged script with no project environment
```

`AGENTS.md` is the operational contract for working in this repo.

## Honest limits

- **A draft cannot be fully graded.** Roughly a third of the checks read headers
  that only exist once a message has been sent and received. Pass `--draft` for an
  unsent message: without it a good draft scores 30 and NO_GO on 8 findings nobody
  can act on. In draft mode the authentication and hygiene sub-scores were skipped
  rather than passed, which the report states. To check those, send it and grade
  the copy that arrives.
- **Blocklist checks need a useful vantage point.** The operators rate-limit or
  refuse queries from residential addresses, so results from a home connection can
  be wrong. `--offline` skips them.
- **A good score is not a promise of delivery.** It means what you control is in
  order. Engagement, list quality, and complaint rate decide placement too, and
  none of them are visible in one message.

## License

MIT.
