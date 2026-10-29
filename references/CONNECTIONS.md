# Connections

Sendable grades a message you already have. These connections give it more to
read: your own mailbox, the reports receivers mail out, and the dashboards the
large providers publish about you.

Nothing here is required. The audit runs on a saved `.eml` with no setup at all.
Each connection below answers a question that one message cannot answer.

| Connection | Answers | Cost | Time |
|---|---|---|---|
| [Mailbox tags](#1-mailbox-tags) | How do reports and test sends reach the agent | free | 10 min |
| [DMARC aggregate reports](#2-dmarc-aggregate-reports) | Who sends as my domain, and does it authenticate | free | 10 min, then 48 h |
| [Google Postmaster Tools](#3-google-postmaster-tools) | What does Gmail think of my domain | free | 5 min |
| [ESP branded subdomain](#4-esp-branded-subdomain) | Are my links and bounces on my own domain | plan-dependent | 15 min |
| [Microsoft SNDS and JMRP](#5-microsoft-snds-and-jmrp) | What does Outlook think of my sending IP | free | 15 min |
| [Yahoo Complaint Feedback Loop](#6-yahoo-complaint-feedback-loop) | Who marked my mail as spam at Yahoo | free | 10 min |
| [Your ESP dashboard](#7-your-esp-dashboard) | Bounce rate, complaint rate, per-campaign engagement | included | 0 min |

Do them in this order. Each one is useful alone, and 1, 2, and 3 cover most of
what a sender needs.

---

## 1. Mailbox tags

**What it gives you.** A way for the agent to collect reports and test sends with
no forwarding rules and no second account.

Plus-addressing means `jane+anything@example.com` is delivered to
`jane@example.com`. Gmail, Google Workspace, Microsoft 365, Fastmail, Proton, and
most self-hosted servers support it with no configuration. The tag after the `+`
stays visible in the recipient headers, which is what keeps the two streams
separable.

Use two tags:

- `jane+reports@example.com` receives the DMARC aggregate reports.
- `jane+check@example.com` receives messages you want graded. Forward or BCC a
  send to it.

**Set it up.**

1. Send a message to `<your-address>+check@<your-domain>`.
2. Confirm it arrives.

If it does not arrive, your provider does not support plus-addressing. A plain
second mailbox such as `dmarc@example.com` works the same way. Everything below
still applies.

**Warning about forwarded messages.** When you forward a send to `+check`, save
the **original** message, not the forwarding wrapper. The audit detects a forward
and recovers the original content, but the authentication headers belong to the
forward. Auth findings then describe the forwarder rather than your real send.
Most mail clients offer "forward as attachment" or "show original". Use that.

---

## 2. DMARC aggregate reports

**What it gives you.** A daily XML file from each large receiver listing every IP
that sent mail claiming to be your domain, and whether each one passed SPF, DKIM,
and alignment. This is the only view that covers **every** recipient. One saved
message covers one.

It is also how you find a sender you forgot: an old form tool, a CRM, a
contractor's account, or somebody spoofing you.

**Set it up.**

1. Read the record you have now.

   ```bash
   dig +short TXT _dmarc.example.com
   ```

   Nothing returned means no DMARC record exists.

2. Publish or update it. Start at `p=none`.

   ```
   Name:  _dmarc.example.com
   Type:  TXT
   Value: v=DMARC1; p=none; rua=mailto:jane+reports@example.com
   ```

   `v=DMARC1` names the standard. `p=none` means take no action on failing mail,
   and only turn reporting on. `rua=` is where the daily reports go.

   Never start at `quarantine` or `reject`. That rejects your own mail before you
   know which of your senders is misconfigured.

3. Wait 24 to 48 hours for the first reports. A useful picture needs about a
   week.

4. Read them and act.

   ```bash
   python3 scripts/dmarc.py ~/Downloads/dmarc/*.gz --pretty
   ```

   Nothing is stored, so keep the files and pass the whole folder each time.
   Every report in it is read and the answer describes all of them together.
   Nothing is compared across them, so a source is reported as these reports
   show it and never as new or returning.

**Sending reports to two places.** Each address needs its own `mailto:` scheme.
This is the most common mistake in a DMARC record:

```
WRONG:   rua=mailto:jane@example.com,ops@vendor.com
RIGHT:   rua=mailto:jane@example.com,mailto:ops@vendor.com
```

RFC 7489 defines the `rua` value as a comma-separated list of URIs, not of email
addresses. An entry with no scheme is not a URI. Some receivers discard that
entry. Some discard the whole tag, and then you get no reports at all.

**Sending reports to another domain.** If the report address is not on your
domain, that domain must publish an authorization record. Check it before you
rely on it:

```bash
dig +short TXT example.com._report._dmarc.vendor.com
```

A `"v=DMARC1"` answer means the vendor accepts reports for your domain. Nothing
returned means receivers will refuse to send them. RFC 7489 §7.1 requires this so
that nobody can point `rua=` at a stranger's mailbox and flood it.

**Climb the policy ladder one rung at a time.** `status` returns a `next_step`
with a `code`. Do that one thing, then wait for new reports. The order is: get
every real sender aligned, then `p=none` to `p=quarantine`, then `p=quarantine`
to `p=reject`.

`status` refuses to recommend advancing while `blockers` is non-empty. A blocker
is a real sender of yours that fails alignment. Tightening the policy then starts
rejecting your own mail, which is worse than doing nothing.

---

## 3. Google Postmaster Tools

**What it gives you.** Gmail's own opinion of your domain: reputation, spam
complaint rate, authentication pass rates, and delivery errors. Gmail is usually
the largest single block of any list, so this is the highest-value dashboard.

**Set it up.**

1. Go to `postmaster.google.com` and add your domain.
2. It gives you a DNS TXT record. Publish it at your apex.
3. Press Verify.

If you already have a `google-site-verification` TXT record for Search Console,
verification is usually instant.

**Add the domain that signs your DKIM, not your bounce subdomain.** Postmaster
Tools groups data by the DKIM signing domain. If your ESP signs with
`d=example.com`, add `example.com`. Adding `send.example.com` as well collects
nothing.

**Expect empty charts at first.** Google does not publish a threshold. The
commonly cited figure is about 100 messages per day to Gmail addresses before
reputation data appears for that day. Below that, most panels stay blank. An
empty chart at low volume means no data, not bad reputation.

**Keep the verification record.** If the TXT record is removed or changed,
Postmaster Tools stops collecting.

**The Domain reputation panel is gone.** The first version of Postmaster Tools
showed a Bad / Low / Medium / High rating for your domain and your IP. Google
retired that version at the end of September 2025, and the second version does
not carry those two panels. Advice that tells you to read your domain reputation
rating is advice written before that date. Nothing replaced it with another
rating.

**Read it in this order.**

| Panel | Target |
|---|---|
| Spam rate | under 0.10%. Google's bulk sender rules treat 0.30% as the limit. |
| Deliverability analysis | one verdict in plain words. See the table below. |
| Compliance status | every row passing. 11 rows, one per bulk sender requirement. |
| Authentication | SPF, DKIM, and DMARC pass rates across every recipient |
| Delivery errors | near zero |

The Authentication panel is the wide version of what the audit measures on one
message. Use both. The audit tells you why one message failed. This tells you
what fraction of all your mail failed.

**Deliverability analysis is the panel that replaced the rating.** It appeared in
June 2026. Instead of a grade it gives one verdict, and the verdict is about what
recipients did, not about how clean your setup is. Google published no
announcement, the names below come from the API reference, and senders report
that it reaches accounts unevenly. So treat an absent panel as not yet arrived.

| Verdict | What it says |
|---|---|
| `USER_FEEDBACK_POSITIVE` | recipients signal they want the mail. This is the target. |
| `USER_FEEDBACK_LOW` | recipients neither complain nor act. See below. |
| `MESSAGE_VOLUME_LOW` | too little mail to judge |
| `USER_FEEDBACK_NEGATIVE` | recipients signal they do not want the mail |
| `SPAM_RATE_HIGH` | spam rate above 0.1% |
| `SENDER_NOT_COMPLIANT` | a bulk sender requirement is failing |
| `SMTP_ERRORS_HIGH` | too many messages are being refused |

**`USER_FEEDBACK_LOW` is the one to understand.** It is not a complaint. It says
recipients open nothing, click nothing, and report nothing. Indifference used to
be invisible, and senders argued about whether it counted. Google now names it as
a state of its own, between wanted and unwanted. A domain can pass all 11
compliance rows and still sit here.

The fix for it is subtraction, not addition. Stop sending to addresses that have
not clicked or replied in 90 to 180 days. Measure clicks and replies rather than
opens, because Apple Mail Privacy Protection and Gmail's image proxy load the
tracking pixel whether or not a person read anything.

---

## 4. ESP branded subdomain

**What it gives you.** Two changes, from one setup:

1. Your envelope sender (the `Return-Path`) moves from the ESP's domain to a
   subdomain of yours. SPF then aligns with your `From:` domain.
2. Your click and open tracking links move from a hostname shared with every
   other customer of that ESP to a hostname on your domain.

Item 2 matters more. A link domain carries reputation. A shared one carries
everybody else's behaviour, and you cannot improve it.

Providers call this different things: branded subdomain, custom return path,
custom tracking domain, sending domain, link branding. It is the same mechanism.

**Set it up.**

1. In your ESP, find the sending domain settings. Choose a subdomain prefix.
   `send` is a good choice. Avoid `mail`, which is the conventional name for an
   inbound mail host and which you may want later.
2. The ESP gives you one or more CNAME records. Publish them.
3. Verify in the ESP.

**Do not put anything of your own on that subdomain.** No MX, no SPF, no A
record. The ESP owns it through the CNAME.

**Do not add the ESP's SPF include to your apex.** This is the counterintuitive
part, and it is the most common wasted change in email setup.

SPF is checked against the **envelope sender** domain, not against the `From:`
header. On a shared ESP pool, the envelope sender is the ESP's own domain. A
receiver reads the ESP's SPF record and never reads yours. Adding
`include:esp.example` to your apex changes nothing in the result.

```
MAIL FROM: <bounces-...@esp.example>   ->  receiver reads SPF of esp.example
From: you@example.com                   ->  never consulted for SPF
```

After branding:

```
MAIL FROM: <...@send.example.com>       ->  receiver reads SPF of send.example.com
From: you@example.com                   ->  same organizational domain  ->  aligned
```

The SPF record that matters lives on the branded subdomain, and the ESP publishes
it there for you through the CNAME. Check it:

```bash
dig +short TXT send.example.com
```

**Your apex SPF record is for your inbound and your other senders.** Leave it
alone when you set up branding.

**Subdomain policy.** Your DMARC record at `_dmarc.example.com` applies to
subdomains unless it carries an `sp=` tag. The branded subdomain inherits your
policy, which is what you want. Do not publish a separate DMARC record for it.

**Verify it on a real send.** Branding can be live in DNS and still not applied
to a campaign template. Send one test, save the `.eml`, and check three things:

- `Return-Path` ends in your branded subdomain
- the body links read your branded subdomain
- `auth.dmarc_alignment_spf` passes in the audit

---

## 5. Microsoft SNDS and JMRP

**What it gives you.** Smart Network Data Services shows Outlook's view of a
sending **IP address**: complaint rate, trap hits, and filter result. The Junk
Mail Reporting Program mails you a copy of each message an Outlook user marks as
junk.

**Both are keyed to an IP address, not to a domain.** This is the limit that
decides whether they are useful to you.

- **On a dedicated IP, set both up.** They are the only direct view of Outlook
  you can get.
- **On a shared ESP pool, you cannot.** You do not own the IP, so you cannot
  verify it. Your ESP owns that relationship. Ask them for their Outlook
  complaint data instead.

Find out which you have. Read the `Received:` header of a message you sent, take
the sending IP, and ask your ESP whether it is yours alone.

**Set it up (dedicated IP only).**

1. Go to `substrate.office.com/ip-domain-management-snds/snds` and request
   access for your IP range. The older
   `sendersupport.olc.protection.outlook.com/snds/` address still redirects
   there. Microsoft moves this page, so check their current sender support page
   if neither loads.
2. Microsoft mails the technical contact in the IP's registration record. You
   must be able to receive that mail.
3. Separately, join JMRP to receive complaint copies.

---

## 6. Yahoo Complaint Feedback Loop

**What it gives you.** A copy of each message a Yahoo, AOL, or Verizon Media user
marks as spam. Use it to remove those addresses at once. A person who complained
and keeps receiving mail complains again, and the second complaint costs more
than the first.

**This one is keyed to your DKIM signing domain**, so it works on a shared ESP
pool. That makes it more useful than SNDS for most senders.

**Set it up.**

1. Confirm your DKIM signing domain. It is the `d=` value in the
   `DKIM-Signature` header of a message you sent.
2. Go to `senders.yahooinc.com/complaint-feedback-loop/`. Create a sender
   profile, add your domain, and verify it.
3. Enroll the verified domain. Give an address that can receive a high volume.
   Use a tag such as `jane+fbl@example.com`.

Yahoo states the requirement plainly: "The Complaint Feedback Loop program only
supports DKIM-signed email and is a domain based service." If your mail is not
DKIM-signed, fix that first.

Most ESPs process these for you automatically and suppress the address. Ask your
ESP before you enroll, so you do not build a second pipeline for nothing.

---

## 7. Your ESP dashboard

**What it gives you.** The two numbers that decide everything, which no DNS
record and no saved message can show: your **bounce rate** and your **complaint
rate**, per campaign.

You already have this. Read it before every send.

| Number | Act when |
|---|---|
| Hard bounce rate | over 2%. Remove every hard bounce before the next send. |
| Complaint rate | over 0.10%. Over 0.30% and Gmail's bulk sender rules are breached. |
| Open rate falling across sends | the list is going stale, or placement is slipping |

Your ESP also tells you which segment opened. That segment is what you send to
first when you warm a domain. See [PLAYBOOKS.md](PLAYBOOKS.md).

---

## What none of this gives you

No connection on this page tells you which folder one specific recipient saw.
Providers do not publish per-recipient placement, and no tool can read it from
outside.

What you can do instead is in [PLAYBOOKS.md](PLAYBOOKS.md), under "One email
landed in three different folders".
