# Playbooks

The audit grades one message. These are the questions it does not answer alone,
with the order of steps that does answer them.

1. [One email landed in three different folders](#1-one-email-landed-in-three-different-folders)
2. [Warm up a new domain](#2-warm-up-a-new-domain)
3. [Everything was fine, and now it is not](#3-everything-was-fine-and-now-it-is-not)
4. [The message bounced, and the code means nothing to me](#4-the-message-bounced-and-the-code-means-nothing-to-me)

---

## 1. One email landed in three different folders

Some recipients found it in the inbox. Some found it in Promotions. Some found it
in spam. The bytes were identical.

**Start with the audit, and expect it to come back clean.**

```bash
uv run scripts/audit.py sent.eml --pretty
```

A high score here is information, not a dead end. It tells you the cause is not
in the message. Placement is then decided per recipient, and the audit has no
window into that.

**The order of causes.** Work through them in this order, because each one only
matters if the one above it is settled.

### Step 1: is the message authenticating

Read `hard_gates_failed` and the `auth.*` findings. If DMARC fails, stop here.
Nothing else explains anything until it passes.

One trap: DMARC passes when SPF **or** DKIM aligns. A failing
`auth.dmarc_alignment_spf` with a passing `auth.dmarc_alignment_dkim` is worth
fixing but did not move placement. Do not chase it first.

### Step 2: is the sending reputation known

This is the usual answer when identical bytes split three ways.

A receiver decides placement from: authentication, then the reputation of your
domain and sending IP, then that specific recipient's own history with you, then
the content, then whether it looks like bulk mail.

When your domain is new, step 2 returns nothing. The receiver has no opinion. So
the decision falls through to the per-recipient signal, which is **different for
every recipient**. That is the mechanism. One message, three answers.

Check whether you are in this state:

- How many campaigns have you sent from this domain? Under about 10 means no
  reputation.
- Is your sending IP shared with other customers of your ESP? Then its
  reputation is not yours to build.
- Does Google Postmaster Tools show anything yet? Empty panels mean the receiver
  has not formed an opinion. Do not go looking for a domain reputation rating:
  Google retired that panel with the first version of Postmaster Tools. Read the
  spam rate and the Deliverability analysis verdict instead. See
  [CONNECTIONS.md](CONNECTIONS.md).

If you are in this state, go to [playbook 2](#2-warm-up-a-new-domain). There is
no fix in the message.

### Step 3: what is the content doing

With no reputation to lean on, content decides more than it normally would. A
reputable sender absorbs a risky subject. A new one does not.

Read the failing `copywriting.*` findings. Pay most attention to subject
findings, because the subject carries the most weight per word.

Vocabulary that overlaps with phishing and fraud corpora costs a new sender more
than the audit's severity suggests: breach, exposed, security issue, verify your
account, rotated, suspended, urgent. This is worst when the mail is a genuine
security notice, because the honest words are the flagged words. Write it plainly
and lead with the outcome for the reader.

### Step 4: why Promotions specifically

Promotions is not a spam decision. It is a sorting decision, made per user, from
markers that say this is bulk commercial mail:

- `List-Id` and `List-Unsubscribe` headers
- an open-tracking pixel
- click-tracking links on a domain that is not yours
- a vendor logo or badge in the footer
- many images relative to text

You cannot remove all of these, and you should not. `List-Unsubscribe` is
required by Gmail's bulk sender rules. What you **can** do is stop the links from
pointing at a shared vendor domain, and remove a free-plan badge. See
[CONNECTIONS.md](CONNECTIONS.md), section 4.

A message with zero links to your own domain and two links to your ESP's
redirector reads as vendor mail, whatever the copy says.

**Do not expect to escape Promotions by stripping the message down.** Senders
report that plain-text messages with no images and no tracking still sort into
Promotions. Treat the markers above as a lever that can move a borderline
message, not as a switch.

**Two things changed about Promotions, and both make escaping it the wrong
goal.**

1. Position inside the tab is now ranked, not chronological. Since September 2025
   Gmail offers a "most relevant" sort, and it puts the senders a reader engages
   with most at the top. Sending more often buys nothing. Engagement history buys
   position.
2. Gmail's AI Inbox reads the Primary tab only. It states this plainly: it
   surfaces information from Primary and not from Social or Promotions. So a
   message in Promotions is invisible to the summary and to-do layer that Gmail
   began adding in January 2026 and extended to paid Workspace accounts in
   October 2026.

Item 2 is the real consequence, and it splits your mail in two. Bulk campaign
mail will sit in Promotions, and no amount of editing moves it. One-to-one mail
from a person can earn Primary, because Gmail picks the readers it treats as
important from frequent correspondents, saved contacts, and relationships it
infers from the message text. For that mail, write the date and the action in
plain words ("reply by Friday 6 November"), and ask for a reply. A reply is the
strongest signal a recipient can send.

### Measure which tab it reached

Inference stops here. Gmail assigns every message a category even when the reader
has tabs turned off, and you can read that category on a Gmail account you
control.

1. Send the message to a Gmail address you own.
2. Search your mailbox for `category:promotions`. The other categories answer the
   same way: `category:primary`, `category:social`, `category:updates`,
   `category:forums`, `category:purchases`, `category:reservations`.
3. To record it rather than read it, build a Gmail filter on
   `category:promotions` that applies a label. A label is visible over IMAP, so
   you can log the tab for every test send instead of looking each one up.

This measures your own account, which has its own engagement history with you.
It tells you the category Gmail assigned. It does not tell you the category a
stranger's account assigned.

### The check that settles it

Everything above is inference from one copy. This is the measurement.

1. Ask one recipient who found it in spam, and one who found it in Promotions, to
   send you the original message as an attachment.
2. Compare three lines against your own copy:

   ```bash
   grep -iE '^Received: from|^Authentication-Results:|^Return-Path:' spam.eml
   grep -iE '^Received: from|^Authentication-Results:|^Return-Path:' promo.eml
   ```

**Read the result:**

| What you see | What it means |
|---|---|
| Different sending IP | ESP pool reputation. Your copies left from different IPs. Ask your ESP, or move to a dedicated IP. |
| Same IP, different auth result | Something modified the message in transit. A forwarder or a gateway. |
| Same IP, same auth result | Per-recipient engagement. Nothing in the message explains it. Go to playbook 2. |

3. Then read the wide view. DMARC aggregate reports cover every recipient, not
   the two who answered you.

   ```bash
   uv run scripts/dmarc.py ~/Downloads/*.xml.gz --domain example.app --pretty
   ```

### What to tell the sender

Lead with the cause, not the finding list. Most of the time it is:

> The email is fine. The audit scored it 90. What split it three ways is that
> your domain is new, so each provider fell back to what each individual
> recipient had done with your mail before. That is different for every person.
> Fix it by sending to the people who already open your mail first, and widening
> from there.

---

## 2. Warm up a new domain

**Decide what you are warming.** This changes the whole plan.

| Your setup | What needs warming |
|---|---|
| Shared ESP IP pool | the **domain** only. The IPs are already warm, and their reputation is not yours. |
| Dedicated IP | the **IP and the domain**. The IP starts at zero and is the harder of the two. |

Read the `Received:` header of a message you sent to get the sending IP, then ask
your ESP which one you have.

### Warming a domain on a shared pool

Receivers build a domain reputation from recipient behaviour, not from volume.
Volume without engagement makes it worse. So the ramp is a **segment** ramp, not
a size ramp.

1. **Clean first.** Remove every hard bounce from your previous sends. A list
   with dead addresses on a new domain is the fastest way into spam.
2. **Send 1: openers only.** Only the people who opened a previous campaign. Your
   ESP has this segment already.
3. **Send 2, about 4 days later.** Add the people who opened an older campaign
   but not the most recent one.
4. **Send 3.** Add everyone else, but only if sends 1 and 2 held under 0.10%
   complaints and under 2% hard bounces.
5. **Hold a rhythm.** Roughly one send every 4 to 5 days. Do not go silent for
   weeks and then send a burst. An irregular pattern reads as a compromised
   domain.

**Ask for replies.** A reply is the heaviest positive signal a receiver has.
"Reply to this and tell me X" in the first third of the message is worth more
than any header change on this page. Use a `From:` name that is a person and a
`Reply-To` that a human reads.

**Stop and fix if** the complaint rate goes over 0.10%, the hard bounce rate goes
over 2%, or Postmaster Tools reports Low or Bad reputation. Do not widen the
segment to recover. Narrow it.

### Warming a dedicated IP

Volume matters here, because an IP earns reputation from throughput.

Roughly double each day, starting small, and hold at each step if the numbers
move the wrong way. A common shape is 50, 100, 500, 1000, 5000, and so on over
about 4 weeks. Send the most engaged segment at every step.

Your ESP almost certainly has a documented schedule and an automatic warm-up
mode. Use theirs. They know their pool.

### Track that it worked

```bash
uv run scripts/audit.py latest-send.eml --pretty
```

The audit keeps no history, so you keep the sends. Audit each one as it goes out
and keep the JSON next to the `.eml`, then the scores are a sequence you can
read. The number that matters while warming is the complaint rate at the
provider, not the score: a clean message to a cold list still gets reported.

---

## 3. Everything was fine, and now it is not

Placement dropped, and nothing obvious changed.

**Audit the last good send and the first bad send.** Then compare them, not just
read them.

```bash
uv run scripts/audit.py good.eml --pretty > good.json
uv run scripts/audit.py bad.eml  --pretty > bad.json
diff <(jq -r '.findings[]|select(.passed==false)|.check' good.json) \
     <(jq -r '.findings[]|select(.passed==false)|.check' bad.json)
```

The diff is the answer. A check that fails in the bad send and passed in the good
one is what changed, and it names itself. Comparing the two scores tells you much
less, because one number can move for several reasons at once.

**Then check the things that change without you touching the message.**

1. **A DNS record changed.** Somebody edited SPF, DKIM, or DMARC. The
   `domain.*` and `auth.*` findings catch this, and the diff above names which
   one.
2. **A new sender appeared on your domain.** A CRM, a form tool, a contractor.
   It sends unaligned mail as you, and your whole domain pays for it.

   ```bash
   python3 scripts/dmarc.py ~/Downloads/dmarc/*.gz --domain example.app --pretty
   ```

3. **Your ESP moved you to a different IP pool.** Compare the sending IP in the
   `Received:` header of the good send and the bad send.
4. **Your list aged.** Open rate falling across several sends, with no change to
   the message, is a list problem, not a message problem.
5. **A blocklist listed you.** The audit checks this on every online run. Read
   the `sending_ip.*` and `url_reputation.*` findings.

**The order matters.** Items 1 and 2 are things you can fix today. Items 3 to 5
take weeks. Rule out the fast ones first.

---

## 4. The message bounced, and the code means nothing to me

A bounce is the one place a receiving provider tells you exactly why, in writing.
It is better evidence than any test, and most senders throw it away because the
string looks like noise.

**Read the raw string, not your ESP's summary.** An ESP groups bounces into
"blocked" or "deferred", and those two words cover six different causes with six
different fixes. Open the bounce message and find the line the receiver sent.

**Fix anything naming Spamhaus first**, before you read any of the rest. A
listing there feeds many receivers at once, so every other reading is distorted
while it stands.

### Gmail

| Code | Cause | The check that names it |
|---|---|---|
| `550 5.7.25` | the delivering address has no name, or its name does not point back to it | `sending_ip.ptr_resolves`, `sending_ip.fcrdns` |
| `550 5.7.26` | neither SPF nor DKIM aligns with your `From:` domain | `auth.dmarc_alignment_overall` |
| `421 4.7.x` that clears | rate limiting. Slow down and retry. | none. Shape your volume. |

`550 5.7.25` is the one senders miss, because authentication looks clean and the
record belongs to the ESP. Check it whenever the auth findings pass and Gmail
still refuses the mail.

### Microsoft, consumer addresses

These are `outlook.com`, `hotmail.com`, `live.com`, and `msn.com`.

| Code | Cause | The check that names it |
|---|---|---|
| `550 5.7.515` | the `From:` domain does not meet the authentication requirement | `auth.spf`, `auth.dkim`, `dmarc_record.published` |
| `S3150` | the delivering address is on Microsoft's own blocklist | `blacklist.*` |
| `SC-004` | too many recipients marked your mail as junk | none. Read JMRP. |
| `SC-001`, `OU-002` | content or reputation | the `copywriting.*` and `content.*` findings |
| `SC-002` | too many attempts at addresses that do not exist | none. This comes from a list-verification tool of yours, not from this audit. Stop verifying addresses by SMTP probe. |
| `451 4.7.x` that never clears | rate limiting tied to reputation, or a volume spike | none. Shape your volume. |

**`550 5.7.515` is the strictest gate any provider publishes.** Microsoft asks
for more than Gmail does. SPF **and** DKIM must both pass, and the domain must
publish DMARC at `p=none` or stricter, aligned with at least one of them.
Microsoft states the requirement for a `From:` domain sending more than 5,000
messages a day to those four domains. Senders report the code on much smaller
volumes, so do not read the threshold as a safe allowance.

Two things to know about it. Microsoft's announcement says the mail is refused,
while Microsoft's own postmaster page still describes sending it to Junk first.
Senders' bounce logs show refusal. And it arrives without warning: a reputation
problem degrades over weeks, while this gate starts refusing overnight.

The string arrives in two spellings. Search your logs for `550 5.7.515` and for
`550; 5.7.515`.

### Microsoft 365 tenants

A tenant is a company's own Microsoft mail, and its administrator sets their own
filtering. A Microsoft delisting does nothing for a tenant-level block.

| Code | Cause | The check that names it |
|---|---|---|
| `550 5.7.509` | your domain publishes DMARC `p=reject` and this message failed DMARC | `auth.dmarc_alignment_overall` |

### What to do with the answer

1. Run the audit on a copy of the message that bounced. The table above names the
   check for each code, so go to that finding and read it.
2. If the named check passes, the cause is not in the message. Go to
   [playbook 3](#3-everything-was-fine-and-now-it-is-not).
3. If no check covers the code, it is reputation or volume. Neither is visible in
   one message. Read your spam rate and complaint rate in
   [CONNECTIONS.md](CONNECTIONS.md).
