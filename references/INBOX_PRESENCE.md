# Being recognised in the inbox

Everything here is about the strip a reader scans before they decide to open:
the picture, the name, the subject. None of it is a defect in the message, so
none of it changes the audit score. The email is correct either way. It simply
does better with a face beside it.

Two routes. Do the free one first.

---

## 1. A picture beside your name in Gmail

**What it does.** Gmail shows a photo next to the sender name when the address
you send from has a Google Account with a photo on it. It applies to mail you
already sent, not only to the next one.

**What it costs.** Nothing, and about five minutes.

**Who sees it.** People reading in Gmail. Other mail apps do not use it, and
several read Gravatar instead.

### The part everyone gets wrong

You need a **Google Account**, which is a login. You do **not** need a Gmail
address, which is a mailbox. They are different things and Google's sign-up
pushes you toward the second one.

You can make a Google Account on the address you already use, whoever hosts it.
A Microsoft address, a company address, anything. Your mail keeps arriving
exactly where it arrives now. Nothing moves.

### Steps

1. Open the Google Account sign-up page. When it offers to create a new address
   ending in `gmail.com`, look for the option to **use an existing email address
   instead** and pick that.
2. Enter the address you actually send from. Google emails a code to it.
   Confirm the code.
3. Go to the account's profile page and upload a photo. Square, at least
   250 by 250 pixels, a JPEG or a PNG.
4. Set who can see the photo to **anyone**. A photo nobody can see is a photo
   Gmail will not show.
5. Give it a day.

### The warning you will see, and why to ignore it

If you ever open Gmail while signed in to this account, Google offers to add an
address ending in `gmail.com`, and the page can read like something is wrong
with your account. Nothing is wrong. Click away from it and do not accept.

Accepting creates a Gmail mailbox you did not ask for. You only need the
account. Declining changes nothing about where your mail is hosted or where it
is delivered.

### Checking it worked

Send a message to a Gmail address you control and look at the list view. If the
photo is not there yet, wait a day before changing anything: the delay is
normal.

---

## 2. A logo record, which the receivers call BIMI

**What it does.** Puts your own logo beside your name, and on Gmail with the
paid certificate, a tick as well. It is the official route and it belongs to
the domain rather than to a person.

**What it costs.** A certificate, renewed every year, if you want the logo in
Gmail or Apple Mail. There are two grades of it, and Apple takes only the
dearer one, which needs a registered trademark. Yahoo, Fastmail and AOL show
the logo with no certificate at all.

**What it needs first.** Your DMARC policy at `quarantine` or `reject`. A
receiver ignores the record entirely while the policy is `none`, so publishing
it early does nothing at all. The audit checks this and will say so.

### Steps

1. Get your DMARC policy to `quarantine`, then `reject`, reading your aggregate
   reports in between so none of your own mail starts bouncing. `dmarc.py` is
   for exactly this.
2. Make a square version of your logo as an SVG, in the plain flavour a
   receiver accepts, under 32 kilobytes, served over `https`.
3. Buy the certificate if you want Gmail to show it.
4. Publish a TXT record at `default._bimi` on your domain, pointing at the logo
   and at the certificate when you have one.
5. Send yourself a message and look at it in Gmail, Yahoo and Apple Mail. They
   do not all behave the same way.

### One more route, unverified here

Apple runs its own scheme, Branded Mail, through Apple Business Connect. It
needs no BIMI certificate and instead reviews your brand directly, and it works
only inside Apple's apps. It is the Apple-shaped version of the Google Account
trick above. I have not confirmed its current terms, so check Apple's own pages
before you spend time on it.

---

## Why these are not scored

A sender with no logo and no photo is not sending a worse email. Marking them
down would say something untrue about the message, and it would push a correct
email below a threshold it should pass. They appear in the report under
`opportunities`, separately from `findings`, and the score ignores them.
