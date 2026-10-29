# Sendable 📬: because nobody tells you why it went to spam, or whether the next one will

[![ci](https://img.shields.io/github/actions/workflow/status/georgebnov/sendable/skill.yml?branch=main&style=flat-square&label=ci)](https://github.com/georgebnov/sendable/actions/workflows/skill.yml)
[![python](https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square)](pyproject.toml)
[![license](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)

Find out why an email lands in spam or Promotions. Grade a message you already
sent, or a draft before it goes out. 124 checks on the message, the
authentication, and the domain, run on your machine. No account, no service,
nothing uploaded.

Built to be driven by an agent. Every command prints JSON, and `SKILL.md` is the
contract an agent reads to know when and how to run it.

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Where this came from](#where-this-came-from)
- [The two things it does](#the-two-things-it-does)
- [When the audit is clean and the email still went to spam](#when-the-audit-is-clean-and-the-email-still-went-to-spam)
- [Connect more data](#connect-more-data)
- [Reference](#reference)
- [Honest limits](#honest-limits)
- [Development](#development)
- [License](#license)

## Install

You need Python 3.11 or newer. Nothing else. Sendable has no dependencies, so
there is nothing to install, no environment to build, and no package index to
reach.

**As a skill, so an agent can use it.** This is an
[Agent Skill](https://agentskills.io): a folder with a `SKILL.md`, which is an
open format that many agents read, not a Claude-only one. Clone it once and link
it wherever your agent looks:

```bash
git clone https://github.com/georgebnov/sendable.git ~/skills/sendable
```

| Agent | Skills directory |
|---|---|
| Any, project-level | `.agents/skills/` |
| Claude Code | `~/.claude/skills/` |
| Codex | `~/.codex/skills/` |
| Cursor | `.cursor/skills/`, and it also reads the Claude and Codex paths |
| Windsurf | `.windsurf/skills/` |

```bash
# pick the one your agent uses, or link it into several
ln -s ~/skills/sendable ~/.claude/skills/sendable
ln -s ~/skills/sendable ~/.codex/skills/sendable
```

The directory the skill sits in has to be named `sendable`, because the spec
requires the folder name to match the `name` in the frontmatter.

A skill is read when a session starts, so start a new one and the agent has it.
From then on `SKILL.md` is the whole contract: the agent reads that to know when
to run an audit, how to read the report, and what to tell you about it.

**To run it yourself**, with no agent involved:

```bash
git clone https://github.com/georgebnov/sendable.git && cd sendable
python3 scripts/audit.py tests/fixtures/clean_bulk.eml --offline --pretty
```

## Quick start

Grade the bundled example. There is nothing to resolve or cache, so the first
run takes about as long as every run after it.

```bash
python3 scripts/audit.py tests/fixtures/clean_bulk.eml --offline --pretty
```

Then grade your own. Save a message from your mail client as `.eml` and run:

```bash
python3 scripts/audit.py mail.eml --pretty     # a message you sent
python3 scripts/audit.py draft.eml --draft     # a message you have not sent yet
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
my spam folder. It wasn't a cold email or a newsletter, it was just a guy
answering a conversation we were already in the middle of, and what got me is
that he had no idea. He thought he had answered me. On his side the email was
sent and that was the end of it.

So if his mail does that to me it does that to his clients too, and nobody ever
tells you. You don't get a bounce or a warning, you just stop hearing back, and
then you decide people aren't interested.

Then I started digging into why, and it turned into a project with him and with
one of the top brokerage consultants in Canada, both of them selling for a living
and both of them losing deals to a folder nobody opens. We built the whole thing
out, a website, accounts, a backend, a real platform. Over 20 companies used it in
beta, we audited over 300 emails, and we pulled sending domains back up by
tracking over 2k DMARC reports.

What I didn't expect is how much of it was already fixable before the send. Most
of the mail we graded wasn't spam, it was ordinary mail with something small and
invisible wrong with it, a record that didn't line up, a subject that read like a
promo, a line of hidden white text the template put there. The sender could have
fixed it in 2 minutes if anyone had told them which 2 minutes.

Then things didn't go the way we planned and we split.

I'm the technical side of it, I built the checks and the scoring and the DMARC
pipeline, so the code was just sitting there and the only question left was
whether anyone ever gets to use it. I decided to stop it as a project but put the
part that was actually worth something out anyway, which is the checks and the
judgement behind them, and released it as a skill anyone can run.

It's the same engine that graded those 300 emails. If you send newsletters or
sales emails you can find out why one of them landed in spam or Promotions, and
you can fix it before the next one goes out instead of after.

## The two things it does

**Grade one email.** The copy and structure of the message, SPF, DKIM, DMARC and
whether they align, MTA-STS, TLSRPT and BIMI records, 31 IP blocklists, 8 URL
blocklists, and a live SMTP probe.

One email in, one verdict out. It reads nothing but the file you give it and
writes nothing anywhere, so a second run on the same bytes gives the same answer.

**Read your DMARC reports.** Receiving providers mail you a daily XML report
listing everything that sent mail claiming to be your domain. Pass them in.

```bash
python3 scripts/dmarc.py ~/Downloads/*.xml.gz --pretty
```

It returns one next step. It will not tell you to tighten your DMARC policy while
a real sender of yours is failing alignment, because that would start rejecting
your own mail.

This answers the one question an audit of a single message cannot: who else sends
as you, and do they authenticate. Pass reports older than the window and it also
separates "a spoof just started" from "your provider added an IP".

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
