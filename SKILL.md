---
name: sendable
description: "Email deliverability audit before you send: inbox placement, spam and Promotions, SPF, DKIM, DMARC alignment, blocklists, copy, and DMARC aggregate reports."
license: MIT
compatibility: Requires uv and Python 3.11 or newer. Network access for the DNS, blocklist and SMTP checks; --offline skips those.
---

# Sendable

Audit an email and tell the sender what to change. Local, no account, no
service, and nothing written to disk.

**Audit one email.** `scripts/audit.py` grades a saved message and answers one
question: will this land, and why. Did it authenticate, does the authentication
align, is the copy going to get filtered, does it carry a working unsubscribe.

124 checks in five groups: 49 on the copy and structure of the message, 11 on
authentication and alignment, 35 on the domain records (SPF, DKIM, DMARC,
MTA-STS, TLSRPT, and BIMI), 15 on the sending infrastructure (31 IP blocklists, 8
URL blocklists, and a live SMTP probe), and 14 on headers and hygiene.

**Read your DMARC reports.** `scripts/dmarc.py` reads the aggregate reports that
receiving providers mail out, works out everything sending as the domain, and
gives the one next step. It answers the question one message cannot: who else
sends as you, and do they authenticate.

## Run it

Nothing to install. `uv` reads each script's own dependency list and caches it.
First run takes a few seconds, later runs take 0.1s.

```bash
# Grade one saved email. Prints the report as JSON. Stores nothing.
uv run scripts/audit.py mail.eml

# Same, no outbound traffic at all: copy and structure checks only.
uv run scripts/audit.py mail.eml --offline

# Grade something not sent yet. Use this for any draft an agent wrote.
uv run scripts/audit.py draft.eml --draft

# From a pipe.
cat mail.eml | uv run scripts/audit.py -

# Read the aggregate reports a provider mailed. .xml, .xml.gz, and .zip all work.
uv run scripts/dmarc.py ~/Downloads/*.xml.gz --pretty

# Say which domain when one batch covers more than one.
uv run scripts/dmarc.py ~/Downloads/*.xml.gz --domain example.com
```

`dmarc.py` stores nothing either. You pass the reports you have, it reads them,
and it prints the answer. Pass more reports to see further back.

**Pass reports older than the window and the answer sharpens.** Anything older
than `--days` becomes the baseline, which is what separates "a spoof just
started" from "your provider added an IP". With a single day of reports that one
judgement is skipped rather than guessed, and the output says so in
`new_sender_detection`.

Both commands print JSON on stdout and progress on stderr, so stdout always
parses. Exit code is 0 on success and 1 when there is nothing to work with.

## Get the message yourself, do not ask for a file

If you have access to the user's mail, use it. Do not ask them to export an
`.eml` and tell you where they put it. The audit reads a message on stdin, so
fetch it and pipe it:

```bash
# whatever your mail access is, write the raw message to stdin
uv run scripts/audit.py - --pretty
```

**Fetch the raw message, not the rendered one.** A Gmail connector, the Gmail
API, or an IMAP client will offer you a plain-text or markdown rendering by
default, and that is the wrong thing. It throws away the headers, and the
headers are where authentication, alignment, TLS, the unsubscribe mechanism and
the Received chain live, which is roughly a third of the checks. Ask for the
original:

- a Gmail MCP tool: the `RAW` message format
- the Gmail API: `messages.get` with `format=raw`, then base64url-decode it
- a mail client by hand: "Show original" in Gmail, or "Save as" / "Download
  message" elsewhere

**Pass the original, not a copy forwarded to yourself.** Forwarding rewrites the
envelope and re-signs the message, so the authentication results you would be
grading are your own forwarder's, not the sender's. The audit notices and says
so, and it reframes the alignment findings rather than blaming the sender, but
the report is still about a different message than the one you meant. If a user
forwards you something to check, grade it and tell them the limit.

**Finding the right message.** The user will describe it, not name it. Search
their mail the way they described it, and when more than one matches, say which
one you picked and why rather than guessing silently. Gmail's own search is
enough: `from:`, `subject:`, `after:`, and `category:promotions` if they are
asking why something was sorted that way.

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

## What to tell the user

Translate every finding into the composer they are actually looking at: the
subject line, the preview-text field, the link they pasted, the From name. Never
hand them an HTML tag, a CSS property, or an RFC number. A marketer cannot act on
"your `display:none` div trips Gmail's salting heuristic". They can act on "delete
the hidden line of white text above your headline".

Name the one thing to change first. A list of fourteen findings is a report; one
sentence saying what to fix is help.

## Judge the copy yourself

The audit grades what a rule can decide. Five questions about the copy need a
reader, not a rule, so the audit does not answer them. **You answer them.** You
are reading the message already, and you are the model this skill runs inside, so
a second model call would do the same work twice.

Read the message and report these five alongside the findings. Each one says what
to look for and how much it matters.

1. **Does the subject promise what the body delivers?** A rule catches `Re:`
   spoofing and a dead subject. It cannot tell whether a subject that promises a
   price drop opens an email about a hiring update. Read both and say so. Treat a
   mismatch as serious: it is the one item on this list that a recipient reports
   as spam rather than ignores.

2. **Does the opening leave a question open?** A surprising number, a question
   the reader cannot answer yet, or a half-told story makes them read on. A
   closed statement ("Here is our March update") lets them stop at the subject.
   Say which it is. Minor on its own.

3. **How many central ideas does the message carry?** One idea, with room, is
   the target. Two dilute each other, and the second usually belongs in its own
   send. Three or more make it a digest the reader skims. Report the count:
   two is worth fixing, three or more is worth rewriting.

4. **Does the body name the state, or only the specification?** A specification
   is a fact. A benefit is what that fact gives the reader. "Quartz countertops"
   is the specification; "a counter you do not have to baby" is the benefit. Say
   whether the body frames benefits, mixes the two, or lists specifications
   alone. Minor, but it is usually the largest single lift available on a message
   that is otherwise clean.

5. **Does the message earn its claims?** A specific number, a named result, a
   study, or a testimonial earns trust inside the body. An assertion with nothing
   behind it reads as a marketing claim. Say which the message does. Minor.

Two rules for how you report them.

Say these are your reading, not a measured result. The score and the verdict come
from the checks, and nothing you judge here moves either. A sender who cannot
tell the two apart will argue with the score.

Keep item 1 separate from the other four. A subject that misleads is a
deliverability problem, because the reader reports it. The other four cost
attention and replies, not placement.

## Playbooks

Four questions arrive more than any others. Each one needs an order of steps,
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
4. **The message bounced, and the code means nothing to me.** A bounce string is
   the receiving provider saying why, in writing. The playbook maps every code
   Gmail and Microsoft send to its cause and to the check that names it.

## Connect more data

The audit needs nothing but the message itself. Each connection in
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

  To check the rest, send it to `+check` and grade the copy that arrives.
- **Blocklist checks need a useful vantage point.** The blocklist operators
  rate-limit or refuse queries from residential addresses, so results from a home
  connection can be wrong. `--offline` skips them.
- **A good score is not a promise of delivery.** It means the things a sender
  controls are in order. Recipient engagement, list quality, and complaint rate
  decide placement too, and none of them are visible in one message.
- **The score does not grade whether the copy is any good.** It grades what a
  rule can decide: length, structure, links, trigger phrases, shouting, reading
  level. Whether the subject matches the body, whether the opening holds a
  reader, and whether the message carries one idea are the five questions under
  "Judge the copy yourself", and they are yours to answer. A message can score 99
  and still be weak writing. Say that plainly rather than letting the number
  stand in for a judgement it never made.

## Files

```
scripts/audit.py        grade one email
scripts/dmarc.py        read aggregate reports, report the next step
engine/                 every check. No database, no state, nothing written.
references/             what to load on demand:
  PLAYBOOKS.md            the questions one audit cannot answer alone
  CONNECTIONS.md          every data source a sender can connect, and how
  CHECKS.md               every check, with its thresholds and severity
  MECHANISMS.md           how the subtle checks decide, step by step
```
