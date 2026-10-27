# Playbooks

The audit grades one message. These are the questions it does not answer alone,
with the order of steps that does answer them.

1. [One email landed in three different folders](#1-one-email-landed-in-three-different-folders)
2. [Warm up a new domain](#2-warm-up-a-new-domain)
3. [Everything was fine, and now it is not](#3-everything-was-fine-and-now-it-is-not)

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
- Does Google Postmaster Tools show a domain reputation yet? Empty means the
  receiver has not formed one. See [CONNECTIONS.md](CONNECTIONS.md).

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
   uv run scripts/dmarc.py ingest ~/Downloads/*.xml.gz
   uv run scripts/dmarc.py status --domain example.app --pretty
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
uv run scripts/reports.py trend --domain example.app
```

The 6 drift checks start reporting from the 3rd audit of a sender. After that,
`trend` answers "is this moving, and which way" instead of you guessing.

---

## 3. Everything was fine, and now it is not

Placement dropped, and nothing obvious changed.

**Audit the last good send and the first bad send.** Then compare them, not just
read them.

```bash
uv run scripts/audit.py good.eml --pretty
uv run scripts/audit.py bad.eml --pretty
uv run scripts/reports.py problems --domain example.app
```

`problems` counts how many stored audits each check failed in, worst first. The
top line is the thing that keeps happening, not the thing that happened most
recently. That is usually the one to fix.

**Then check the things that change without you touching the message.**

1. **A DNS record changed.** Somebody edited SPF, DKIM, or DMARC. The
   `domain.*` and `auth.*` findings catch this. The drift checks name it
   directly when you have 3 or more audits of the sender.
2. **A new sender appeared on your domain.** A CRM, a form tool, a contractor.
   It sends unaligned mail as you, and your whole domain pays for it.

   ```bash
   uv run scripts/dmarc.py senders --domain example.app --pretty
   ```

3. **Your ESP moved you to a different IP pool.** Compare the sending IP in the
   `Received:` header of the good send and the bad send.
4. **Your list aged.** Open rate falling across several sends, with no change to
   the message, is a list problem, not a message problem.
5. **A blocklist listed you.** The audit checks this on every online run. Read
   the `sending_ip.*` and `url_reputation.*` findings.

**The order matters.** Items 1 and 2 are things you can fix today. Items 3 to 5
take weeks. Rule out the fast ones first.
