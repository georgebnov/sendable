# Security

## Reporting a vulnerability

Report privately through GitHub's
[Report a vulnerability](https://github.com/georgebnov/sendable/security/advisories/new)
form. Please do not open a public issue for anything exploitable.

Include what you did, what happened, and what you expected. A fixture that
reproduces it is the most useful thing you can send.

Expect an acknowledgement within a week. This is a small project with no security
team and no bounty, so treat those as honest expectations rather than a guarantee.

## What this tool does with your data

Everything runs on your machine. Nothing is uploaded, and there is no service or
account behind it.

Two things leave your machine, both only when you ask for them:

**DNS and SMTP lookups.** An audit reads the sending domain's SPF, DKIM, DMARC,
MTA-STS, TLSRPT, and BIMI records, queries 31 IP blocklists about the sending IP and 8 URL blocklists about the links, and
opens an SMTP connection to the domain's mail server. Those queries reveal the
domain you are auditing to your resolver and to the blocklist operators.
`--offline` skips all of it.

`--probe-unsub` is off by default because it fetches a URL taken from the email
under audit, which is a URL an attacker chose. When you do enable it,
`_is_public_http_url` refuses a private address, a loopback address, a link-local
address such as a cloud metadata endpoint, a non-HTTP scheme, and a disallowed
port. That guard has its own tests in `tests/test_ssrf_gate.py`.

## What is stored, and where

`.sendable/` holds your audit history as plain JSON. It contains real subject
lines, real link URLs, your sending domains, and the authentication results of
your mail. It is gitignored by default. Committing it is a deliberate choice, and
sharing it is a disclosure.

Reports in `.sendable/dmarc/` list every IP that sent mail claiming to be your
domain, which is information about your infrastructure.

## Reading untrusted email

An email under audit is untrusted input, and some of it is hostile by design: the
hidden-text check exists because senders embed prompt-injection text in white
text. The audit treats message content as data throughout, and XML is parsed with
`defusedxml` to block entity expansion and external entity attacks.

If you pass a report to a model yourself, remember that a `message` or `details`
field can contain text an attacker wrote.

## Supported versions

The latest release only. There is no backport branch.
