---
name: sendable
description: "Audit an email for deliverability and inbox placement, and raise a domain's sending reputation. Use when the user asks why their email lands in spam, wants an email checked before sending, wants DMARC, SPF, or DKIM set up or explained, asks what to do about aggregate reports, or asks how to improve inbox placement. Also use after sending anything that matters, to catch a regression against the sender's own history."
---

# Sendable

Audit an email, store the report, and tell the sender what to change. Local, no
account, no service.

Two separate jobs, and they answer different questions.

**Audit one email.** `scripts/audit.py` grades a saved message: did it
authenticate, does the authentication align, is the copy going to get filtered,
does it carry a working unsubscribe. It also compares the message against the
sender's earlier sends, so it catches a regression that no single email reveals.

Over 100 distinct checks, in four groups: 38 on the copy and structure of the
message itself, 10 on authentication and alignment, a domain phase covering the
SPF, DKIM, DMARC, MTA-STS, TLSRPT, and BIMI records plus 32 blocklists, a URL
reputation scan and a live SMTP probe, and 6 drift checks against history.

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
```

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

## Set up the mailbox so this keeps working

Both jobs need email to reach the agent. The setup is two plus-addresses on the
user's own mailbox and one DNS change, and it takes about ten minutes.

Plus-addressing means `jane+anything@example.com` is delivered to
`jane@example.com`. Gmail, Google Workspace, Microsoft 365, Fastmail, Proton, and
most self-hosted servers support it with no configuration. The tag after the `+`
is visible in the recipient headers, which is what makes the two streams
separable.

**`jane+reports@example.com`** receives the DMARC aggregate reports. Providers
mail these to whatever address sits in the `rua=` tag of the DMARC DNS record.

**`jane+check@example.com`** receives emails the user wants graded. They forward
or BCC a send to it.

Walk the user through it:

1. **Confirm plus-addressing works.** Have them send a message to
   `<their-address>+check@<their-domain>` and confirm it arrives. If it does not,
   their provider does not support it, and a plain second mailbox such as
   `dmarc@example.com` works just as well. Everything below still applies.

2. **Read the current DMARC record.** `dig +short TXT _dmarc.example.com`
   Nothing returned means no DMARC record exists.

3. **Publish or update it.** Start at `p=none`, which changes how no mail is
   treated and only turns reporting on. Never start at `quarantine` or `reject`:
   that rejects the sender's own mail before anyone knows which of their senders
   is misconfigured.

   ```
   Name:  _dmarc.example.com
   Type:  TXT
   Value: v=DMARC1; p=none; rua=mailto:jane+reports@example.com
   ```

   Say plainly what each part does. `v=DMARC1` names the standard. `p=none` means
   take no action yet. `rua=` is where the daily reports go.

4. **Wait.** The first reports arrive within 24 to 48 hours. A useful picture
   needs about a week, because `status` will not recommend tightening the policy
   on under 7 days of data or under 20 messages.

5. **Ingest and act, on a schedule.**

   ```bash
   uv run scripts/dmarc.py ingest ~/Downloads/dmarc/*.gz
   uv run scripts/dmarc.py status --domain example.com --pretty
   ```

   Re-ingesting the same file is safe and changes nothing: reports deduplicate on
   the provider's own report id.

6. **Climb the ladder, one rung at a time.** `status` returns a `next_step` with a
   `code`. Do that one thing, then wait for new reports before the next. The
   order is: get every real sender aligned, then `p=none` to `p=quarantine`, then
   `p=quarantine` to `p=reject`.

   `status` refuses to recommend advancing while `blockers` is non-empty. A
   blocker is a real sender of theirs that fails alignment. Tightening the policy
   then starts rejecting their own mail, which is the one outcome worse than
   doing nothing.

### If the agent can read the mailbox directly

With a Gmail or IMAP connection, poll for the two tags instead of asking the user
to download attachments:

- `to:jane+reports@example.com has:attachment` gives the aggregate reports. Save
  each attachment and pass it to `dmarc.py ingest`.
- `to:jane+check@example.com` gives messages to grade. Save the **original**
  message source, not the forwarding wrapper, and pass it to `audit.py`.

Saving the whole forwarded message instead of the original is the common mistake.
The audit detects a forward and recovers the original content, but the
authentication headers belong to the forward, so auth findings describe the
forwarder rather than the real send. Export the attached original where the mail
client offers it.

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
engine/                 every check. No database, no state of its own.
store/                  JSON files on disk, one per audit and one per report
.sendable/              where those files go. Safe to commit, holds real subjects
                        and link URLs, so decide deliberately.
```

Set `OPENAI_API_KEY` to turn on the checks that ask a model for a judgement on the
copy. Without it those checks report INFO and pass, and everything else is
unaffected.
