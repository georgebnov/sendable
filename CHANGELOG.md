# Changelog

Entries describe user-visible behaviour. They land with the work, under
`Unreleased`, and move into a version section at release. See
[docs/RELEASING.md](docs/RELEASING.md).

## Unreleased

**Highlights:** First release as a skill. Audit an email, read your DMARC
aggregate reports, and track both locally. No service, no account, no database.

### Added

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

### Fixed

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

### Removed

- The hardcoded industry check registry. It was unreachable: no caller ever passed
  an industry, so its three real-estate checks never ran.
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
