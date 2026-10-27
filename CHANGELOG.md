# Changelog

Entries describe user-visible behaviour. They land with the work, under
`Unreleased`, and move into a version section at release. See
[docs/RELEASING.md](docs/RELEASING.md).

## Unreleased

Version numbering restarts here. The SaaS reached 0.45.0, but that line described
a hosted product with a different surface, so continuing it would imply a
compatibility this shares none of.

**Highlights:** First release as a skill. Audit an email, read your DMARC
aggregate reports, and track both locally. No service, no account, no database.

### Added

- Playbook 4, "The message bounced, and the code means nothing to me". It maps
  every bounce code Gmail and Microsoft send to its cause and to the check in
  this tool that names it: 550 5.7.25, 550 5.7.26 and 421 4.7.x at Gmail,
  550 5.7.515, S3150, SC-001, SC-002, SC-004, OU-002 and 451 4.7.x at consumer
  Microsoft, and 550 5.7.509 at a Microsoft 365 tenant.
- A way to measure which Gmail tab a message reached, in playbook 1. Gmail
  assigns every message a category even with tabs turned off, and a search for
  `category:promotions` on an account you own reads it back. A filter on the same
  term applies a label, which is visible over IMAP, so a tab can be logged for
  every test send.

- Audit one saved email with `scripts/audit.py`, covering copy and structure,
  SPF, DKIM and DMARC and whether they align, MTA-STS, TLSRPT and BIMI records,
  31 IP blocklists, 8 URL blocklists, a live SMTP probe, and 6 checks that compare
  the send against the sender's own earlier sends.
- Grade an unsent message with `--draft`, which skips the checks that read headers
  only a server can add. Without it a well-written draft scored 30 and NO_GO on 8
  findings its writer could not act on; with it the same draft scores 99.
- Store every audit as one JSON file under `.sendable/audits/`, written once and
  never changed, so the 6 drift checks have history to compare against. They begin
  reporting from the third audit of a sender.
- Read DMARC aggregate reports with `scripts/dmarc.py ingest`, accepting plain
  XML, gzip, and zip, since providers send all three. Re-ingesting a report stores
  nothing, so a re-read cannot double a message count.
- Report the one next step for a domain with `scripts/dmarc.py status`, which
  reads the live SPF and DMARC records as well as the stored reports and refuses
  to recommend tightening a policy while a real sender is failing alignment.
- List everything sending as a domain with `scripts/dmarc.py senders`, collapsing
  a provider's many IPs into one row.
- Track the stored set with `scripts/reports.py`: `trend` for how the score is
  moving, `problems` for what keeps failing worst first, `senders` for one row per
  sending domain, `list`, and `show`.
- Run any script with no install step. Each one carries a PEP 723 dependency
  header, so a caller needs only `uv`.
- `SKILL.md`, the agent-facing contract, including the mailbox setup that routes
  DMARC reports to `<you>+reports@` and messages to grade to `<you>+check@`.
- `references/CONNECTIONS.md`, the setup for every data source a sender can connect:
  mailbox tags, DMARC aggregate reports, Google Postmaster Tools, an ESP branded
  subdomain, Microsoft SNDS and JMRP, the Yahoo complaint feedback loop, and the
  ESP dashboard. Each entry says what it answers, what it costs, and what it
  cannot do. SNDS is keyed to an IP address, so it is useless on a shared pool.
- `references/PLAYBOOKS.md`, for the three questions one audit cannot answer alone: why
  one email reached three different folders, how to warm a new domain, and what
  to compare when placement drops with no obvious cause. A clean audit on a
  message that still went to spam is information, not a dead end, and the first
  playbook says what to measure next.

### Fixed

- Reject a DMARC report address written without `mailto:`. `rua=mailto:a@x,b@y`
  has one URI and one bare address. RFC 7489 defines the value as a list of URIs,
  so receivers drop the bare one and some drop the whole tag, which can leave a
  sender with no reports at all while the record looks right to them. The parser
  used to strip the scheme when present and take the address when absent, so the
  audit called that record fine. New check `dmarc_record.report_uri_syntax`, HIGH
  when it fails. **This adds a check, so a domain audited before may score
  differently.**

- Stop reporting a correct Ed25519 DKIM key as dangerously weak. The key size was
  measured against a 1024-bit RSA floor, and RFC 8463 defines Ed25519 for DKIM
  because a 256-bit curve key is stronger than 2048-bit RSA in a smaller record.
- Name the provider when mail is signed only by a third party, instead of
  reporting "DKIM is not configured". The mail is signed; the key simply is not
  the sender's, so it cannot align for DMARC.
- Declare `cryptography` and `pyasn1`, which the DKIM check used without
  declaring. Key size had been estimated from the DER byte length instead of read
  from the key.
- Remove dashes from the DMARC policy advice, per the house copy rule.
- Say what not to do when SPF is unaligned. The finding named the fix and stopped,
  so senders edited the record called SPF, which is their apex record, and added
  the ESP there. That changes nothing: receivers check SPF against the envelope
  sender, which on a shared ESP pool is the ESP's own domain. The message now
  names the mechanism and both actions.

### Changed

- Say that Gmail can refuse a message whose delivering address has no matching
  name, and name the code it sends: 550 5.7.25. The two reverse DNS findings said
  "a hard deliverability hit" and "penalised", which sends the reader to the spam
  folder to look for a message that was never accepted.
- Replace the Google Postmaster Tools "Domain reputation" panel in
  `references/CONNECTIONS.md` and `references/PLAYBOOKS.md`. Google retired the
  first version of Postmaster Tools at the end of September 2025, and the second
  version does not carry the domain and IP reputation ratings. The documents now
  describe the Deliverability analysis panel that replaced them, its 7 verdicts,
  and what `USER_FEEDBACK_LOW` means: recipients who neither complain nor act.
- State what cannot be fixed about the Promotions tab. Stripping a message down
  does not reliably move it. Position inside the tab is ranked by engagement, and
  Gmail's AI Inbox reads the Primary tab only, so a campaign in Promotions is
  invisible to it. One-to-one mail can still earn Primary.

- Take the industry vocabulary out of the two checks that carried it. The tool
  grades any sender, and a word list built around one trade graded that trade and
  said nothing about the rest.
  - The From display-name check no longer flags `realty`, `properties`, or
    `homes`. It now flags `ltd`, `plc`, and `gmbh` next to the `inc`, `llc`, and
    `corp` it already read. The words that remain name a group or a legal entity
    in any trade.
  - The spam-trigger list loses its one trade-specific category. `insider access`
    moves into `fomo` and `investment opportunity` into `financial-promise`, so
    both still fire. `prices and floorplans attached`, `floorplans attached`,
    `platinum agent`, and `builder direct` are gone. `guaranteed roi` and
    `guaranteed rental` are gone as separate entries, because `guaranteed` in
    `financial-promise` already matches both.
  - **This changes a judgement.** An email that fired only the deleted phrases
    now reports one fewer promotional category, so its `compound_signal`
    severity can fall by one step. The list holds 5 promotional categories
    instead of 6, and `compound_signal` reports CRITICAL at 5, so CRITICAL now
    needs every one of them. An email reaches it only if it also carries a
    generic greeting such as "dear valued customer".

### Removed

- The `VERSION` file. Nothing read it, and it still said `0.45.0` from the SaaS
  while `pyproject.toml` said `0.1.0`. The version has one home now.

- The hardcoded industry check registry. It was unreachable: no caller ever passed
  an industry, so its three vertical checks never ran.
- The LLM humanization layer. It could not be imported at all, because it used
  `python-dotenv` without declaring it, and nothing imported it so nothing noticed.
  In a skill the host agent does that translation, which `SKILL.md` specifies.

### Internal

- Bring all 14.6k lines of the engine under ruff, ruff format, and mypy, none of
  which previously ran on it. Nothing is excluded.
- Add 387 tests and a 69% coverage floor, enforced in CI. The suite makes no
  network call and no model call: `conftest.py` clears `OPENAI_API_KEY` and blocks
  `socket.gethostbyaddr`, because the ESP fingerprint makes a blocking PTR lookup
  inside what reads like pure classification code.
- Run the gate on Python 3.11 and 3.14, plus a second job that runs the packaged
  script from a bare checkout with no project environment, which is the only way
  to catch a dependency missing from a PEP 723 header.
