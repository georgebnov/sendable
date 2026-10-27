---
name: sendable
description: "Find out why an email lands in spam or Promotions, fix it before you send, and raise a domain's sending reputation. Use for inbox placement, open rates, SPF, DKIM, DMARC, aggregate reports, warming a new sending domain, or grading a draft. Also after any send that matters, to catch a regression."
---

# Sendable

Audit an email, store the report, and tell the sender what to change. Local, no
account, no service.

Two separate jobs, and they answer different questions.

**Audit one email.** `scripts/audit.py` grades a saved message: did it
authenticate, does the authentication align, is the copy going to get filtered,
does it carry a working unsubscribe. It also compares the message against the
sender's earlier sends, so it catches a regression that no single email reveals.

135 checks in six groups: 54 on the copy and structure of the message, 11 on
authentication and alignment, 35 on the domain records (SPF, DKIM, DMARC,
MTA-STS, TLSRPT, and BIMI), 15 on the sending infrastructure (31 IP blocklists, 8
URL blocklists, and a live SMTP probe), 14 on headers and hygiene, and 6 drift
checks against the sender's own history.

**Fix the domain.** `scripts/dmarc.py` reads the aggregate reports that receiving
providers mail out, works out everything sending as the domain, and gives the one
next step. This is what raises reputation over weeks.

## Run it

Nothing to install. `uv` reads each script's own dependency list and caches it.
First run takes a few seconds, later runs take 0.1s.

```bash
# Grade one saved email. Writes the report to .sendable/ and prints it as JSON.
uv run scripts/audit.py mail.eml

# Same, no outbound traffic at all: copy and structure checks only.
uv run scripts/audit.py mail.eml --offline

# Grade something not sent yet. Use this for any draft an agent wrote.
uv run scripts/audit.py draft.eml --draft

# From a pipe.
cat mail.eml | uv run scripts/audit.py -

# Store aggregate reports the provider mailed. .xml, .xml.gz, and .zip all work.
uv run scripts/dmarc.py ingest ~/Downloads/*.xml.gz

# The one next step for this domain.
uv run scripts/dmarc.py status --domain example.com --pretty

# Everything sending as this domain, busiest first.
uv run scripts/dmarc.py senders --domain example.com --pretty

# Read what is already stored. Nothing here audits or writes.
uv run scripts/reports.py trend          # is the score moving, and which way
uv run scripts/reports.py problems       # what keeps failing, worst first
uv run scripts/reports.py senders        # one row per sending domain
uv run scripts/reports.py list           # every audit, newest first
uv run scripts/reports.py show <sha>     # one full report
```

Every `reports.py` subcommand takes `--json`. Without it the output is a table for
a person to read. `--domain` narrows `trend`, `problems`, and `list` to one sender.

`problems` is the most useful of the five. It counts how many stored audits each
check failed in, worst first, so the top line is the thing that keeps happening
rather than the thing that happened most recently.

Every command prints JSON on stdout and progress on stderr, so stdout always
parses. Exit code is 0 on success and 1 when there is nothing to work with.

## Reading an audit report

```json
{ "score": 26, "verdict": "NO_GO", "sub_scores": {...},
  "hard_gates_failed": ["auth.dmarc_alignment_overall"],
  "findings": [ { "check": "...", "severity": "HIGH", "passed": false,
                  "message": "...", "details": {...} } ] }
```

Read it in this order:

1. `hard_gates_failed`. A hard gate caps the score no matter how clean everything
   else is. Nothing else matters until these are clear.
2. Findings where `passed` is false, worst `severity` first: CRITICAL, HIGH,
   MEDIUM, LOW, INFO.
3. `sub_scores`, to see which area is dragging: authentication, domain_records,
   infrastructure, hygiene, copywriting.

`verdict` is GO at 85 and above, REVIEW at 65, NO_GO below that.

A finding with `severity: "INFO"` and `passed: true` saying "insufficient history"
is not a problem. It means a drift check had nothing to compare against yet. Those
start reporting from the 3rd audit of a sender.

## What to tell the user

Translate every finding into the composer they are actually looking at: the
subject line, the preview-text field, the link they pasted, the From name. Never
hand them an HTML tag, a CSS property, or an RFC number. A marketer cannot act on
"your `display:none` div trips Gmail's salting heuristic". They can act on "delete
the hidden line of white text above your headline".

Name the one thing to change first. A list of fourteen findings is a report; one
sentence saying what to fix is help.

## Playbooks

Three questions arrive more than any others. Each one needs an order of steps,
not a single command. `references/PLAYBOOKS.md` holds them:

1. **One email landed in three different folders.** Some recipients got the
   inbox, some Promotions, some spam, from identical bytes. A clean audit here
   is information: it means the cause is reputation, not the message. The
   playbook gives the order of causes and the one measurement that settles it.
2. **Warm up a new domain.** What you warm depends on whether your sending IP is
   shared or dedicated, and the two plans are different. On a shared pool you
   ramp by segment, not by volume.
3. **Everything was fine, and now it is not.** What to compare, and which causes
   you can fix today against which take weeks.

## Connect more data

The audit needs nothing but a saved `.eml`. Each connection in
`references/CONNECTIONS.md` answers a question that one message cannot:

| Connection | Answers |
|---|---|
| Mailbox tags | how reports and test sends reach the agent |
| DMARC aggregate reports | who sends as this domain, and does it authenticate |
| Google Postmaster Tools | what Gmail thinks of this domain |
| ESP branded subdomain | are the links and bounces on the user's own domain |
| Microsoft SNDS and JMRP | what Outlook thinks of a **dedicated** sending IP |
| Yahoo Complaint Feedback Loop | who marked the mail as spam at Yahoo |
| The ESP dashboard | bounce rate, complaint rate, engagement per campaign |

Mailbox tags, DMARC reports, and Postmaster Tools cover most of what a sender
needs. Set them up in that order.

Two rules from that document are worth stating here, because agents get both
backwards:

- **SPF is checked against the envelope sender, not the `From:` header.** On a
  shared ESP pool the envelope sender is the ESP's domain, so the receiver reads
  the ESP's SPF record and never reads the user's. Adding the ESP's `include:` to
  the user's apex SPF record changes nothing. The fix for a failing
  `auth.dmarc_alignment_spf` is the ESP's branded subdomain, which moves the
  envelope sender onto the user's own domain. Tell the user not to touch their
  apex SPF record.
- **Each address in a DMARC `rua=` needs its own `mailto:`.**
  `rua=mailto:a@x.com,b@y.com` is malformed, and some receivers discard the whole
  tag and send nothing. Write `rua=mailto:a@x.com,mailto:b@y.com`.

## What it cannot tell you

Say these plainly rather than implying a guarantee.

- **A draft cannot be fully graded.** Roughly a third of the checks read headers
  that only exist once a message has been sent and received: the DKIM signature,
  the SPF result, alignment, TLS, the Received chain, and the Date and Message-ID
  the sending server adds.

  **Always pass `--draft` for a message that has not been sent.** Without it a
  well-written draft scores 30 and NO_GO, with 8 failing findings that the writer
  cannot act on, burying the one that was real. With it the same draft scores 99.

  In draft mode the `authentication` and `hygiene` sub-scores were **skipped, not
  passed**. Do not tell the user their authentication is fine on the strength of a
  draft audit. The `sender.draft_mode` finding lists exactly what was skipped in
  `details.skipped_checks`, and names those two sub-scores in
  `details.unverified_sub_scores`.

  A draft is not stored, because a row with no authentication results would make a
  clean sender look like it had started failing in every later drift comparison.

  To check the rest, send it to `+check` and grade the copy that arrives.
- **Blocklist checks need a useful vantage point.** The blocklist operators
  rate-limit or refuse queries from residential addresses, so results from a home
  connection can be wrong. `--offline` skips them.
- **A good score is not a promise of delivery.** It means the things a sender
  controls are in order. Recipient engagement, list quality, and complaint rate
  decide placement too, and none of them are visible in one message.

## Files

```
scripts/audit.py        grade one email
scripts/dmarc.py        ingest reports, report the next step
scripts/reports.py      read what the store already holds
engine/                 every check. No database, no state of its own.
store/                  JSON files on disk, one per audit and one per report
.sendable/              where those files go. Holds real subjects and link URLs,
                        so decide deliberately before committing it.
references/             what to load on demand:
  PLAYBOOKS.md            the questions one audit cannot answer alone
  CONNECTIONS.md          every data source a sender can connect, and how
  CHECKS.md               every check, with its thresholds and severity
  MECHANISMS.md           how the subtle checks decide, step by step
```

Set `OPENAI_API_KEY` to turn on the checks that ask a model for a judgement on the
copy. Without it those checks report INFO and pass, and everything else is
unaffected.
