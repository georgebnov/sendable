# Sendable 📬

[![ci](https://img.shields.io/github/actions/workflow/status/georgebnov/sendable/skill.yml?branch=main&style=flat-square&label=ci)](https://github.com/georgebnov/sendable/actions/workflows/skill.yml)
[![python](https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square)](pyproject.toml)
[![license](https://img.shields.io/github/license/georgebnov/sendable?style=flat-square)](LICENSE)

Find out why an email lands in spam or Promotions, and fix it before you send the
next one. 135 checks on the message, the authentication, and the domain, run on
your machine. No account, no service, nothing uploaded.

Built to be driven by an agent. Every command prints JSON, and `SKILL.md` is the
contract an agent reads to know when and how to run it.

## Install

There is no install step. You need [`uv`](https://docs.astral.sh/uv/), and each
script declares its own dependencies.

```bash
git clone https://github.com/georgebnov/sendable.git && cd sendable
```

## Quick start

Grade the bundled example. The first run takes a few seconds while `uv` resolves
and caches. Later runs take 0.1 seconds.

```bash
uv run scripts/audit.py tests/fixtures/clean_bulk.eml --offline --pretty
```

Then grade your own. Save a message from your mail client as `.eml` and run:

```bash
uv run scripts/audit.py mail.eml --pretty     # a message you sent
uv run scripts/audit.py draft.eml --draft     # a message you have not sent yet
```

You get a score, a verdict, and a list of findings:

```json
{ "score": 90, "verdict": "GO",
  "sub_scores": { "authentication": 83, "copywriting": 74, "domain_records": 100 },
  "hard_gates_failed": [],
  "findings": [ { "check": "copywriting.subject_word_count", "severity": "MEDIUM",
                  "passed": false,
                  "message": "Subject is 14 words. Trim to 6 to 10 words." } ] }
```

Read `hard_gates_failed` first, then the failing findings worst-severity first.
`verdict` is GO at 85, REVIEW at 65, and NO_GO below that.

## Where this came from

I was going back and forth over email with a real estate agent in Canada, top 20
in the country, and one day I went looking for his reply and found it sitting in
my spam folder. And it wasn't a cold email or a newsletter, it was just a guy
answering a conversation we were already in the middle of, and what got me is
that he had no idea it was happening. If his mail does that to me it does that to
his clients too, and nobody tells you, you just stop hearing back and you assume
people aren't interested.

So I started digging into why, and it turned into a project with him and with a
top brokerage consultant in Canada, both of them selling for a living and both of
them losing deals to a folder nobody opens. We built the whole thing out. A
website, accounts, a backend, a real platform. Over 20 companies used it in beta,
we audited over 300 emails, and we tracked over 2k DMARC reports to pull sending
domains back up.

Then things didn't go the way we planned and we split.

I'm the technical side of it. I built the checks, the scoring, the DMARC
pipeline, all of it. So the code was sitting there and the only question left was
whether anyone ever gets to use it, and I decided to stop it as a project but put
all of it out anyway, so I pulled out the part that was actually worth something,
which is the checks and the judgement behind them, and released it as a skill
anyone can run.

It's the same engine that graded those 300 emails. If you send newsletters or
sales emails, you can find out why one of them landed in spam or Promotions, and
you can fix it before the next one goes out instead of after.

## The two things it does

**Grade one email.** The copy and structure of the message, SPF, DKIM, DMARC and
whether they align, MTA-STS, TLSRPT and BIMI records, 31 IP blocklists, 8 URL
blocklists, a live SMTP probe, and 6 checks that compare this send against the
sender's earlier ones.

That last group is the reason reports are stored. "Your DMARC policy went from
reject to none" and "this display name has never appeared before" are statements
about a sequence. No amount of looking at one message produces them. They start
reporting from the third audit of a sender.

**Fix the domain.** Receiving providers mail you a daily XML report listing
everything that sent mail claiming to be your domain. Feed those in.

```bash
uv run scripts/dmarc.py ingest ~/Downloads/*.xml.gz
uv run scripts/dmarc.py status --domain example.com --pretty
```

`status` returns one next step. It will not tell you to tighten your DMARC policy
while a real sender of yours is failing alignment, because that would start
rejecting your own mail.

**Read what is stored.** Nothing here audits or writes.

```bash
uv run scripts/reports.py trend      # is the score moving, and which way
uv run scripts/reports.py problems   # what keeps failing, worst first
uv run scripts/reports.py list       # every audit, newest first
```

`problems` is the most useful. It counts how many stored audits each check failed
in, so the top line is the thing that keeps happening rather than the thing that
happened most recently.

## When the audit is clean and the email still went to spam

That happens, and it is not a bug. The audit grades what you control in the
message. Placement is also decided by your sending reputation and by what each
individual recipient has done with your mail before, and neither is visible in one
message.

[`references/PLAYBOOKS.md`](references/PLAYBOOKS.md) covers the three cases:

1. **One email landed in three different folders.** Identical bytes, three
   results. The order of causes, and the one measurement that settles it.
2. **Warm up a new domain.** What you warm depends on whether your sending IP is
   shared or dedicated, and the two plans are not the same.
3. **Everything was fine, and now it is not.** What to compare, and which causes
   you can fix today.

## Connect more data

The audit needs nothing but a saved `.eml`.
[`references/CONNECTIONS.md`](references/CONNECTIONS.md) has the setup for every
source that tells you something one message cannot:

| Connection | Answers | Time |
|---|---|---|
| Mailbox tags | how reports and test sends reach you | 10 min |
| DMARC aggregate reports | who sends as your domain, and does it authenticate | 10 min |
| Google Postmaster Tools | what Gmail thinks of your domain | 5 min |
| ESP branded subdomain | are your links and bounces on your own domain | 15 min |
| Microsoft SNDS and JMRP | what Outlook thinks of a dedicated sending IP | 15 min |
| Yahoo Complaint Feedback Loop | who marked your mail as spam at Yahoo | 10 min |
| Your ESP dashboard | bounce rate, complaint rate, engagement | 0 min |

All free. Do the first three and you have covered most of what a sender needs.

## Reference

| File | What |
|---|---|
| [`SKILL.md`](SKILL.md) | the contract an agent reads |
| [`references/CHECKS.md`](references/CHECKS.md) | every check, with its thresholds |
| [`references/MECHANISMS.md`](references/MECHANISMS.md) | how the subtle checks decide |
| [`references/PLAYBOOKS.md`](references/PLAYBOOKS.md) | the questions one audit cannot answer |
| [`references/CONNECTIONS.md`](references/CONNECTIONS.md) | the data sources you can connect |

## Where things go

```
.sendable/audits/     one JSON file per audited email
.sendable/dmarc/      one JSON file per aggregate report, grouped by domain
```

Plain JSON on disk, written once and never changed. The query these answer is
"the last 30 sends from this sender", so a database would add a schema and a
binary file and buy nothing at this size. Files also version in git, so you can
diff your own history, and one immutable file per record cannot be corrupted by
two writers.

They hold real subject lines and link URLs. `.sendable/` is gitignored by
default, and committing it is a deliberate choice.

Set `OPENAI_API_KEY` to turn on the checks that ask a model to judge the copy.
Without it those report INFO and pass, and nothing else changes.

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
- **Nobody can read per-recipient placement from outside.** No provider publishes
  which folder one specific person saw. Any tool that claims to know is guessing.

## Development

```bash
just check     # lint, types, tests, coverage floor. What CI runs.
just coverage  # per-file coverage, worst first
just smoke     # run the packaged script with no project environment
```

`AGENTS.md` is the operational contract for working in this repo, and
[`CONTRIBUTING.md`](CONTRIBUTING.md) is the short version.

## License

MIT.
