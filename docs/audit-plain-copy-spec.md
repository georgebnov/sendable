# Audit findings: plain-copy + personalized how-to spec

Goal: a non-technical user (marketer, realtor, "Franc") opens an audit and knows
**exactly what's wrong and exactly how to fix it**, without asking an engineer.
Three changes:

1. **Kid-simple card copy** — no jargon in the visible text.
2. **Personalized "How do I fix this?"** — exact steps for *their* detected
   provider, not generic advice.
3. **Forward muting** — a forwarded email still shows the scrambled checks, but
   they're muted (de-emphasized, not scored), so the score isn't wrecked.

No banners. Everything lives on the card itself.

---

## 1. Card anatomy

Each finding card has three layers, most-human first:

```
[ TITLE ]              kid-simple, verb-first, no acronym
one sentence           what's wrong + the real cost (spam) + that it's fixable
▸ How do I fix this?   personalized, provider-specific numbered steps
▸ Show technical       the current jargon (check=, dkim_d=, headers) — engineers only
```

The marketer reads the title + sentence and clicks "How do I fix this?".
The engineer clicks "Show technical details". Same finding, two audiences.

### Writing rules (apply to every card)

- **Metaphor, not mechanism.** "stamp / mark / lock / guest list", never DKIM,
  SPF, DMARC, TLS, alignment, ESMTPS, receiver, credit.
- **Name the real cost.** "might go to spam" / "inbox apps won't trust it".
  Nobody cares about "DMARC alignment"; everybody cares about landing in spam.
- **One action.** "turn on the stamp", not "configure your ESP".
- **Reassure it's fixable + one-time** where true.
- **Grade-5 reading level.** If a word needs email knowledge to parse, cut it.

---

## 2. Personalization: how the "how-to" is chosen

The audit already knows the sender's provider from the same signals the
sender-identity engine uses (`esp_fingerprint.resolve_identity`): the DKIM `d=`,
the Received chain, the SPF includes. Map that to a provider, then show that
provider's steps.

| Detected signal | Provider | How-to playbook |
|---|---|---|
| `*.gappssmtp.com`, `google.com` hops | Google Workspace / Gmail | Google steps |
| `outlook.com`, `protection.outlook.com` | Microsoft 365 | Microsoft steps |
| `sender-sib.com`, `sendinblue` | Brevo | Brevo steps |
| `mailchimp`, `mcsv.net`, `rsgsv.net` | Mailchimp | Mailchimp steps |
| `sendgrid.net` | SendGrid | SendGrid steps |
| `*.kit.com`, `convertkit` | Kit (ConvertKit) | Kit steps |
| none matched | Unknown | generic steps + "who sends your email?" prompt |

DNS-record changes (SPF/DMARC/DKIM TXT) also need the **domain host** (registrar).
We usually can't detect that, so those steps end with: "add this record where you
manage your domain (GoDaddy, Namecheap, Cloudflare, etc.) — here's how for the
common ones," plus a link. Where the tool can generate the exact record value,
show it with a Copy button (already done for the BIMI + DMARC records).

---

## 3. The findings, rewritten

For each: **Title** / sentence / How-to (personalized examples). Technical
details column = keep the existing message verbatim behind the expander.

### DKIM not aligned / not signing (the stamp)

- **Title:** Your emails aren't stamped as really coming from you
- **Sentence:** Your emails go out without your stamp, so Gmail and Outlook can't
  be sure they're really from you and might drop them in spam. You set the stamp
  up once.
- **How do I fix this? (Google Workspace):**
  1. Go to admin.google.com and sign in as the admin.
  2. Apps → Google Workspace → Gmail → Authenticate email.
  3. Pick your domain, click Generate new record.
  4. Copy the record it gives you.
  5. Add it where you manage your domain (your DNS host).
  6. Come back and click Start authentication.
- **How do I fix this? (Brevo):** Senders & IPs → Domains → your domain →
  Authenticate → copy the records Brevo shows → add them at your DNS host →
  click Verify.
- **Microsoft 365 / Mailchimp / SendGrid:** same shape, that tool's "authenticate
  your domain" screen.

### SPF not aligned / ESP not in SPF (the guest list)

- **Title:** Your sending tool isn't on your approved list
- **Sentence:** The app you send from isn't listed as allowed to send for you, so
  inbox apps see mail "from you" coming from a stranger and get suspicious. One
  line added to your domain fixes it.
- **How do I fix this?:** shows the exact line to add for the detected ESP, e.g.
  Brevo → `include:spf.sendinblue.com`, SendGrid → `include:sendgrid.net`, then:
  "add this to your domain's approved-senders line (SPF) at your DNS host."
  Generate/patch the full record when we can, with a Copy button.

### DMARC missing or monitor-only (the rule)

- **Title (missing):** Anyone can pretend to be you
- **Sentence:** You don't have a rule telling inbox apps what to do with fake
  emails using your name, so scammers can spoof you. Adding one record starts
  protecting you.
- **Title (p=none):** Your anti-fake rule is only watching, not blocking
- **Sentence:** You're watching for fakes but not stopping them yet. Once you've
  watched for a few weeks and your real mail passes, tighten it so fakes get
  blocked.
- **How-to:** show the exact `v=DMARC1; ...` record with Copy (already built),
  plus "add it at your DNS host" with the registrar links.

### TLS / encrypted delivery (the lock)

- **Title:** Your email was sent without a lock on it
- **Sentence:** This email went out without encryption on its last step, and Gmail
  and Outlook now block mail that isn't encrypted. Most tools have the lock on by
  default; check it's turned on.
- **How-to (provider-specific):** where to confirm secure/TLS sending is enabled
  in the detected tool. (For forwards this is muted — see §4.)

### Hidden zero-width / invisible characters

- **Title:** There's invisible junk hidden in your text
- **Sentence:** Your text has invisible characters mixed in, which spam filters
  read as someone trying to hide something. Clearing them makes your email look
  honest.
- **How-to:** "Paste your text into a plain notepad first, then back into your
  email tool — that strips the invisible characters. They usually sneak in when
  copying from Word, Docs, or another email."

### No visible unsubscribe link (the way out)

- **Title:** People can't easily unsubscribe
- **Sentence:** Gmail and Yahoo now require a clear way to opt out, or they push
  your mail toward spam. Add a plain "unsubscribe" link near the bottom.
- **How-to:** provider-specific — most ESPs add this automatically via a footer /
  merge tag; show where to enable the unsubscribe footer in the detected tool.

### Too many links (link density)

- **Title:** Too many links for this much text
- **Sentence:** Lots of links in a short email looks promotional to spam filters.
  Keep the one or two that matter, or add more words around them.
- **How-to:** none needed — it's an edit, not a setting. (Copywriting findings
  are already marketer-facing via the LLM; keep as-is.)

*(Extend the same way for: image-to-text ratio, list-unsubscribe header,
BIMI logo, reply-to, look-alike characters, etc. Same three-layer pattern.)*

---

## 4. Forward detection + muting

A forwarded email (e.g. "Fwd: …") has its stamp, lock, and text rewritten by the
forwarding mailbox, so the auth/hygiene checks grade the *forward*, not the
campaign. This tanked a healthy domain to 9/100 and confused a non-technical user.

**Detect a forward** when any strong signal holds:
- Subject matches `^\s*(Fwd|Fw|FW):`
- DKIM `d=` is a mailbox-provider forward-signer (`*.gappssmtp.com`, etc.) not
  aligned to the From domain
- Received chain shows a mailbox-provider forward hop

**On a forward, mute the scrambled checks** (do NOT drop them):
- Still shown in the list.
- **Excluded from the score** (reuse the scorer's existing "down-weight
  findings that aren't the user's fault" path — see `report.py`).
- Visually de-emphasized: a "muted" tier, not the red "FIX NOW".
- Small inline tag on each: **"not scored — forwarded copy"**.

Muted set: DKIM alignment, SPF alignment, overall DMARC alignment, TLS transport,
zero-width / hidden characters, header-integrity checks.

Keep scoring normally: copywriting, subject, link density, unsubscribe presence,
engagement — a forward doesn't distort the words.

Net: the user sees "these are muted because you forwarded it, send a direct test
for a real read" **on the affected cards**, no banner, and the score reflects only
what's really gradeable.

---

## 5. Implementation notes (for the build session)

- **Where copy lives:** the hardcoded `Finding(message=...)` strings in
  `app/domain/audit/domain/**` (auth, dns, integrity) and
  `app/domain/audit/copywriting/**`. Rewrite the visible message; move the
  current text into a structured detail the UI shows under "Show technical
  details".
- **Card model:** add fields to `Finding` (or a UI-facing layer): `title`,
  `plain` (the sentence), `how_to` (list of steps), `technical` (current text),
  `muted: bool`. Or keep `message` = plain and add `how_to` + `technical` +
  `muted`.
- **Provider detection:** reuse `esp_fingerprint.resolve_identity` /
  `classify` to get the provider name from the parsed email, then key a
  `HOW_TO[provider][check_id]` playbook table. Fall back to generic + "who sends
  your email?".
- **Forward detection:** new helper alongside `mode.detect`; sets a
  `forwarded` flag on the report and marks the muted checks.
- **Scoring:** muted findings use the existing non-user-fault down-weight so the
  score excludes them.
- **Tests:** forwarded .eml → scrambled checks present but `muted=True` and
  excluded from score; a Google-signed sender → DKIM how-to shows Google steps;
  a Brevo sender → Brevo steps.

Reading-level check on every new string: grade 5. No acronym in any visible line.
