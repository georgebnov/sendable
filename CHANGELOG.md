# Changelog

Entries describe user-visible behaviour. They land with the work, under
`Unreleased`, and move into a version section at release. See
[docs/RELEASING.md](docs/RELEASING.md).

## Unreleased

Version numbering starts at 0.1.0. This is the first release of the skill.

**Highlights:** First release as a skill. Audit an email, or read your DMARC
aggregate reports, and get back what to change. Nothing is written to disk. No
service, no account, no database.

### Added

- A new part of the report, `opportunities`, for the two ways to be recognised
  in the inbox. Neither is a defect, so neither changes the score: an email
  with no logo is not a worse email, and marking it down would push a correct
  message below a threshold it should pass.
- The free one, which the audit always offers because nothing in a message
  reveals whether it is done. Gmail shows a picture beside the sender name when
  the sending address has a Google Account with a photo on it, and it applies
  to mail already sent. The step people get wrong is that a Google Account is a
  login and not a mailbox: it can be made on the address they already use, on
  any host, and accepting Google's offer of an address ending in `gmail.com` is
  the mistake. The page that offers it reads like a warning, so the steps say
  so before anyone meets it.
- The paid one, a logo record, whose state the audit reads from DNS: already
  published, ready to add, or blocked until the DMARC policy reaches quarantine
  or reject. It names the yearly certificate cost up front, because finding
  that out after publishing the record is the wrong order.
- `references/INBOX_PRESENCE.md` holds both in full.

- A section in `SKILL.md` telling the host agent to make the five copy
  judgements the audit stopped making: whether the subject promises what the body
  delivers, whether the opening leaves a question open, how many central ideas
  the message carries, whether the body names the state or only the
  specification, and whether the message earns its claims. The skill runs inside
  a model, so the model that reads the report answers them. Each item carries the
  criteria and how much it matters.
- A limit in `SKILL.md`: the score does not grade whether the copy is any good.
  It grades what a rule can decide. A message can score 99 and still be weak
  writing, and the number must not stand in for a judgement it never made.

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
- Read DMARC aggregate reports with `scripts/dmarc.py`, accepting plain XML,
  gzip, and zip, since providers send all three. It reads the live SPF and DMARC
  records alongside them, reports the one next step, lists everything sending as
  the domain with a provider's many IPs collapsed into one row, and refuses to
  recommend tightening a policy while a real sender is failing alignment.
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

- The DMARC advice no longer offers a weaker record than the one already
  published. A domain is placed on the policy ladder by the highest rung it has
  passed, not by the first rung of its policy. A domain at `p=reject; pct=90`
  used to be counted as being at 25 percent, so the step after it was 50, and
  the advice read "Nothing is failing. The next step is reject at 50%" while
  handing over a record that drops the domain from 90 to 50. A downgrade
  presented as progress, on the one setting where going backwards re-opens the
  domain to spoofing. A domain below the lowest rung of its policy, such as
  `p=quarantine; pct=10`, is now offered 25 rather than 50, so no rung is
  skipped.

- The DMARC report reader makes no claim about time at all. It used to count
  the distinct dates inside a batch and present the total as a span, which is
  wrong: a user can download one report today and the next six months from now,
  so the files are a pile and not a timeline. `days_with_data` has left the
  output, the advice counts messages and never days, and the caution it carries
  is the one that survives without a calendar: a report only shows what sent
  while it was being written, so anything absent from it is what breaks when
  the policy tightens.
- `dmarc.py` stopped pretending to track anything. It reads the reports you
  pass, says what is in them, and gives the next step. The policy advice used to
  be gated on a 21 day clean streak and a message count, and told anyone with
  less "Keep collecting reports. We'll prompt you once there's enough clean
  volume." Nothing collects and nothing prompts, so that advice could never be
  acted on. The advice now always names the next rung, states how many days and
  messages the reports cover, and leaves the reader to judge whether that is a
  fair sample of how they send.
- A sender is recognised by the curated list of providers, not by having
  appeared in an older file you happened to pass. A named host nobody
  recognises, failing both SPF and DKIM, now reads as a possible spoof rather
  than as an authentication gap. The old answer changed depending on which
  files were in the folder, which is not a judgement worth making.
- Gone with the tracking: the clean streak, the new-sender flag, the recurring
  gap escalation, and the `first_seen` column. `clean_streak_days`,
  `new_sender_detection`, `window_days` and `reports_as_baseline` have left the
  JSON output.
- `dmarc.py` reads every report you pass and the `--days` flag is gone. It used
  to judge a trailing window and treat anything older as the baseline, which
  only works when reports arrive continuously, the way they did when a service
  collected them. Nothing collects them now, so a normal batch of a few recent
  files landed entirely inside the window, left nothing for the baseline, and
  switched new-sender detection off exactly when someone was looking. A sender
  is now new when it appears only in the newest reporting period and in none
  before it, which needs no calendar and works for a batch of any age or shape.
  A week of daily reports used to report `new_sender_detection: false`. It now
  reports `true` and names the sender that just appeared.

- Stop telling a sender to escalate an IP that does not exist. When the audit
  recognised the sending platform, it rewrote every failing reverse DNS finding
  to name that platform. One of those findings is the note saying no sending
  address could be read from the message at all, which a forwarded message
  produces. That note became "[ESP outbound IP: SendGrid] No sender IP
  recoverable ... forward the finding to their deliverability team", which names
  an address that was never found and asks the reader to escalate a check that
  was skipped. The rewrite now touches only the two findings that are about an
  address.

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

- The store, and everything that existed to serve it. The MVP answers one
  question, will this email land and why, and that needs the file rather than a
  history. Gone: `.sendable/`, the 6 drift checks that compared a send against
  earlier ones, `scripts/reports.py`, and the `--store` and `--no-store` flags.
  Checks go from 130 to 124, and the `engagement` sub-score goes with them.

  **Neither entry point writes to disk now.** The audit prints its report and
  keeps nothing. `scripts/dmarc.py` lost its subcommands: you pass the report
  files and it prints the answer. Reports older than the window become the
  baseline for new-sender detection, so that capability survives with no state
  on disk, and the output says in `new_sender_detection` whether it had one.

- Every call to a third-party API, and the checks that made them. The audit asked
  a model to judge five things about the copy: whether the subject matched the
  body, whether the opening created an open loop, whether the message carried one
  idea, whether it framed benefits over features, and whether it showed social
  proof. In a skill the host agent reads the report and is itself a model, so the
  tool paying for a second one was work done twice.

  Gone with them: `engine/llm.py`, the `openai` dependency from both
  `pyproject.toml` and the `scripts/audit.py` header, the `OPENAI_API_KEY`
  paragraph from `SKILL.md`, `README.md` and `SECURITY.md`, and the test fixture
  that cleared the variable.

  **The engine now reads no environment variable at all.** `grep -rn os.environ`
  over `engine/`, `store/` and `scripts/` returns nothing, so there is no key to
  set, nothing to leak, and one less disclosed network surface in `SECURITY.md`.

  The count drops from 135 checks to 130, and the copy group from 54 to 49.

- Three dead functions. `is_known_legit` in the sending-platform fingerprint,
  with its constant: nothing called it, and its own docstring said it served "the
  classifier's new-IP branch", which no longer calls it. `_peel_signature` in the
  body extractor, a wrapper that called `_peel_signature_with_tail` and dropped
  the tail. `_selectors_from_signatures` in the DKIM check, labelled a
  "back-compat shim" with no caller.
- The paragraphs in `AGENTS.md` and `docs/README.md` that pointed at a private
  rules file and at a documentation tree that no longer exists.
- The "Coverage status" section of `references/CHECKS.md`. It claimed the rubric
  was "comprehensive for every check ID emitted by the current codebase", and the
  section immediately below it said the file describes 104 of 136. Both could not
  be true. The remaining section says what the file does not cover, states its
  entry count, and gives the command that checks the number.

- Everything that was not the skill. This repository is the audit engine, its
  two entry points and the documents an agent reads, and nothing else. With the
  last of it gone, rule 2 holds without an exception: `extend-exclude` is off
  `pyproject.toml`, and the workflow skips no directory.

- The `VERSION` file. Nothing read it, and it disagreed with
  `pyproject.toml`. The version has one home now.

- The hardcoded industry check registry. It was unreachable: no caller ever passed
  an industry, so its three vertical checks never ran.
- The LLM humanization layer. It could not be imported at all, because it used
  `python-dotenv` without declaring it, and nothing imported it so nothing noticed.
  In a skill the host agent does that translation, which `SKILL.md` specifies.

### Internal

- Removed every dependency. The skill is standard library only, so
  `python3 scripts/audit.py mail.eml` runs it with nothing installed and no
  package index to reach. BeautifulSoup, dnspython, pydantic, lxml, cryptography,
  pyasn1, defusedxml and confusable-homoglyphs are gone, replaced by code this
  repository owns and the gates check. The replacements removed three false
  findings on the way: a key that could not be read was reported as weak, a
  Russian or Greek newsletter was reported as a homoglyph attack, and a hostile
  aggregate report escaped as an unhandled exception.
- Fixed a scoring bug nobody could see. Sub-scores were built by iterating a
  set, and Python randomises string hashing per process, so two audits of the
  same message printed their categories in a different order every run.

- Deleted the configuration the removed SaaS left behind. Three files still
  excluded a `production/` directory that no longer exists, which contradicted
  the rule that nothing is excluded from the gates. Two comments described a
  record store and a `.env` file that the repository does not have.

- Bring all 14.6k lines of the engine under ruff, ruff format, and mypy, none of
  which previously ran on it. Nothing is excluded.
- Add 387 tests and a 69% coverage floor, enforced in CI. The suite makes no
  network call and no model call: `conftest.py` clears `OPENAI_API_KEY` and blocks
  `socket.gethostbyaddr`, because the ESP fingerprint makes a blocking PTR lookup
  inside what reads like pure classification code.
- Run the gate on Python 3.11 and 3.14, plus a second job that runs the packaged
  script from a bare checkout with no project environment, which is the only way
  to catch a dependency missing from a PEP 723 header.
