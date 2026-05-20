# Checks Rubric

Every check the audit runs, 1-by-1, with GOOD / MEDIUM / BAD thresholds and the in-code severity.

Reading guide:
- **GOOD** = condition for PASS (no finding or INFO).
- **MEDIUM** = warn / advisory. `n/a` means check is binary pass/fail.
- **BAD** = fail condition.
- **Severity** = severity emitted in code (LOW / MEDIUM / HIGH / CRITICAL / INFO).

Sections: Domain Health → Email Auth → Headers → Bulk Compliance → Body / Content → Microsoft EOP → Drift.

---

## Domain Health — SPF (`audit/domain_health/checks/spf.py`)

### spf_record.published
- File: `audit/domain_health/checks/spf.py:130-147`
- Validates: SPF TXT record exists at sender domain.
- GOOD: `v=spf1` TXT present.
- MEDIUM: n/a
- BAD: No SPF record.
- Severity: HIGH (fail) / INFO (pass)

### spf_record.multiple_records
- File: `audit/domain_health/checks/spf.py:148-165`
- Validates: Only one SPF record published (RFC 7208 §3.2).
- GOOD: Single record.
- MEDIUM: n/a
- BAD: Multiple records → PermError at receivers.
- Severity: HIGH / INFO

### spf_record.syntax
- File: `audit/domain_health/checks/spf.py:197-211`
- Validates: SPF syntax (mechanisms/modifiers recognized).
- GOOD: No syntax issues.
- MEDIUM: n/a
- BAD: Unknown mechanism or modifier.
- Severity: HIGH / INFO

### spf_record.chars_after_all
- File: `audit/domain_health/checks/spf.py:213-226`
- Validates: Nothing after `all` directive.
- GOOD: Nothing after `all`.
- MEDIUM: Mechanisms after `all` (ignored by receivers).
- BAD: n/a
- Severity: MEDIUM (warn) / INFO

### spf_record.duplicate_include
- File: `audit/domain_health/checks/spf.py:228-242`
- Validates: No duplicate `include:` directives.
- GOOD: No dupes.
- MEDIUM: n/a
- BAD: Duplicate includes (lint).
- Severity: LOW / INFO

### spf_record.ptr_mechanism
- File: `audit/domain_health/checks/spf.py:244-260`
- Validates: Avoids deprecated `ptr` mechanism.
- GOOD: No `ptr`.
- MEDIUM: `ptr` present (deprecated, slow, unreliable).
- BAD: n/a
- Severity: MEDIUM / INFO

### spf_record.redirect_with_all
- File: `audit/domain_health/checks/spf.py:262-278`
- Validates: Avoids `redirect=` together with `all`.
- GOOD: One or neither.
- MEDIUM: Both present (`all` wins, `redirect` dead).
- BAD: n/a
- Severity: MEDIUM / INFO

### spf_record.included_lookups
- File: `audit/domain_health/checks/spf.py:280-298`
- Validates: ≤10 DNS lookups (RFC 7208).
- GOOD: count ≤ 10.
- MEDIUM: n/a
- BAD: count > 10 → PermError.
- Severity: HIGH / INFO

### spf_record.void_lookups
- File: `audit/domain_health/checks/spf.py:300-317`
- Validates: ≤2 void lookups (RFC 7208 §4.6.4).
- GOOD: ≤2.
- MEDIUM: >2 (over cap = PermError).
- BAD: n/a
- Severity: MEDIUM / INFO

### spf_record.recursive_loop
- File: `audit/domain_health/checks/spf.py:319-332`
- Validates: No recursive include chain.
- GOOD: No loop.
- MEDIUM: n/a
- BAD: Loop detected.
- Severity: HIGH / INFO

---

## Domain Health — DKIM (`audit/domain_health/checks/dkim.py`)

### dkim_record.published
- File: `audit/domain_health/checks/dkim.py:159-206`
- Validates: DKIM public key TXT at `<selector>._domainkey.<domain>`.
- GOOD: Record found.
- MEDIUM: n/a
- BAD: No record (selector wrong / not configured).
- Severity: HIGH / INFO

### dkim_record.public_key
- File: `audit/domain_health/checks/dkim.py:209-225`
- Validates: `p=` tag non-empty.
- GOOD: Key present.
- MEDIUM: n/a
- BAD: `p=` empty → key revoked.
- Severity: HIGH / INFO

### dkim_record.key_bits
- File: `audit/domain_health/checks/dkim.py:231-262`
- Validates: Key bit length.
- GOOD: ≥2048-bit.
- MEDIUM: 1024-bit (floor; upgrade recommended).
- BAD: <1024-bit (Gmail/Yahoo bulk reject).
- Severity: HIGH (<1024) / LOW (=1024) / INFO (≥2048)

### dkim_record.syntax
- File: `audit/domain_health/checks/dkim.py:264-295`
- Validates: DKIM record tags valid; no `t=y` test mode.
- GOOD: All tags recognized, no testing flag.
- MEDIUM: `t=y` present or unknown tag (receivers may downgrade).
- BAD: n/a
- Severity: MEDIUM / INFO

### dkim_record.h_coverage_unsubscribe
- File: `audit/domain_health/checks/dkim.py:299-328`
- Validates: DKIM `h=` covers `List-Unsubscribe` + `List-Unsubscribe-Post`.
- GOOD: Both headers signed.
- MEDIUM: n/a
- BAD: One or both unsigned → tamperable in transit (Gmail/Yahoo bulk).
- Severity: HIGH / INFO

### dkim_record.canonicalization
- File: `audit/domain_health/checks/dkim.py:349-406`
- Validates: DKIM `c=` canonicalization (RFC 6376 §3.5) is `relaxed/relaxed`. Default when `c=` absent is `simple/simple` per spec.
- GOOD: `c=relaxed/relaxed`.
- MEDIUM: n/a
- BAD: n/a (both tag values are syntactically valid; this is an advisory only)
- ADVISORY (body, primary risk): body canonicalization is `simple` — ESP footer insertion or relay whitespace mutation breaks the body hash on almost every bulk send. Message leads with this.
- ADVISORY (header, secondary risk): header canonicalization is `simple` — minor; only relays that aggressively refold long headers break the signature.
- Severity: LOW (advisory, single finding ID covers both risk tiers; `details.primary_risk` + `details.risk_tiers` differentiate in the report) / INFO (pass on relaxed/relaxed)
- Notes: Skipped when DKIM-Signature header absent (brute-force selector mode) — no `c=` tag to read. Tag is syntactically valid either way, so this advisory does not surface in `dkim_record.syntax`. When both header and body are `simple`, the body advisory leads in the message; header is appended after.

---

## Domain Health — DMARC (`audit/domain_health/checks/dmarc.py`)

### dmarc_record.published
- File: `audit/domain_health/checks/dmarc.py:51-98`
- Validates: DMARC TXT at `_dmarc.<domain>` or inherited from org domain.
- GOOD: Record present (own or inherited).
- MEDIUM: n/a
- BAD: No DMARC at domain or parent.
- Severity: HIGH / INFO

### dmarc_record.org_domain_fallback
- File: `audit/domain_health/checks/dmarc.py:71-80`
- Validates: Subdomain DMARC inherited from org domain (RFC 7489 §6.6.3).
- GOOD: Inherited correctly.
- MEDIUM: n/a
- BAD: n/a
- Severity: INFO

### dmarc_record.multiple_records
- File: `audit/domain_health/checks/dmarc.py:100-113`
- Validates: One DMARC record.
- GOOD: Single record.
- MEDIUM: n/a
- BAD: Multiple → receivers ignore both.
- Severity: HIGH / INFO

### dmarc_record.syntax
- File: `audit/domain_health/checks/dmarc.py:115-147`
- Validates: Tag syntax (p, sp, pct, adkim, aspf, rua, ruf, fo).
- GOOD: All valid.
- MEDIUM: n/a
- BAD: Unknown tag / invalid policy / pct out of range.
- Severity: HIGH / INFO

### dmarc_record.policy_enabled
- File: `audit/domain_health/checks/dmarc.py:149-168`
- Validates: Policy enforcement strength. Note: Gmail / Yahoo / Microsoft accept `p=none` as the **minimum compliance bar** — sender is technically compliant either way. Framed as an upgrade-path advisory, not a failure.
- GOOD: `p=quarantine` or `p=reject` (protects domain from spoofing).
- MEDIUM: n/a
- BAD: n/a (no fail state — `p=none` is compliant)
- ADVISORY: `p=none` — monitor-only, meets compliance minimum but offers no spoofing protection. Upgrade path: review aggregate (rua) reports ~30 days → `p=quarantine` → `p=reject`.
- Severity: LOW (advisory, p=none) / INFO (pass on quarantine/reject)

### dmarc_record.external_validation
- File: `audit/domain_health/checks/dmarc.py:166-198`
- Validates: External rua/ruf authorized via `<sender>._report._dmarc.<recipient>`.
- GOOD: Authorized.
- MEDIUM: External destination missing authz TXT (reports won't deliver).
- BAD: n/a
- Severity: MEDIUM / INFO

---

## Domain Health — DNS Infra (`audit/domain_health/checks/dns_infra.py`)

> **Scope note:** Deliverability-only. Receivers (Gmail / Microsoft / Yahoo) verify forward+reverse DNS on the **sending IP** (covered in SMTP Probe + Auth sections), not zone administration of the sender domain. SOA values, nameserver redundancy, and serial format are DNS-ops hygiene — they do not affect inbox placement. Previous SOA + multi-NS checks removed for that reason.

### dns.ns_records_published
- File: `audit/domain_health/checks/dns_infra.py:30-50`
- Validates: NS records exist for the sender domain. Without NS, the whole zone (SPF / DKIM / DMARC / MX) is unresolvable.
- GOOD: ≥1 NS record present.
- MEDIUM: n/a
- BAD: No NS records (DNS broken).
- Severity: HIGH / INFO

---

## Domain Health — Modern Records (`audit/domain_health/checks/modern_records.py`)

> **Scope note:** MTA-STS and TLSRPT govern **inbound** TLS enforcement and reporting for your own mail server — they are **not outbound deliverability factors**. Gmail / Microsoft / Yahoo do not penalize spam scoring for missing or broken MTA-STS / TLSRPT. Kept in the audit as operator hygiene but all severities are LOW/INFO so a clean-delivering sender is not falsely down-scored. BIMI is brand-logo display (Gmail / Apple) — pure upside, optional.

### mta_sts.published
- File: `audit/domain_health/checks/modern_records.py:98-118`
- Validates: TXT at `_mta-sts.<domain>` (inbound TLS-strict transport advertised).
- GOOD: Record found.
- MEDIUM: n/a
- BAD: n/a (not deliverability-relevant)
- ADVISORY: Missing — inbound security hardening not advertised.
- Severity: LOW (advisory) / INFO

### mta_sts.multiple_records
- File: `audit/domain_health/checks/modern_records.py:120-135`
- Validates: One MTA-STS record.
- GOOD: Single.
- MEDIUM: n/a
- BAD: n/a
- ADVISORY: Multiple records — inbound TLS policy broken; no outbound impact.
- Severity: LOW (advisory) / INFO

### mta_sts.syntax
- File: `audit/domain_health/checks/modern_records.py:137-155`
- Validates: Required `id=` tag.
- GOOD: Present.
- MEDIUM: n/a
- BAD: n/a
- ADVISORY: Missing `id=`.
- Severity: LOW (advisory) / INFO

### mta_sts.policy_fetch
- File: `audit/domain_health/checks/modern_records.py:157-175`
- Validates: HTTPS GET `https://mta-sts.<domain>/.well-known/mta-sts.txt`.
- GOOD: 200 OK fetch.
- MEDIUM: n/a
- BAD: n/a
- ADVISORY: Fetch fails (HTTP error / SSL error / timeout) — inbound TLS enforcement broken for senders that honor MTA-STS; no outbound impact.
- Severity: LOW (advisory, was HIGH) / INFO

### mta_sts.policy_syntax
- File: `audit/domain_health/checks/modern_records.py:177-195`
- Validates: Policy file has version, mode, max_age, mx.
- GOOD: All fields valid.
- MEDIUM: n/a
- BAD: n/a
- ADVISORY: Missing / invalid fields.
- Severity: LOW (advisory, was HIGH) / INFO

### tlsrpt.published
- File: `audit/domain_health/checks/modern_records.py:202-220`
- Validates: TXT at `_smtp._tls.<domain>` — inbound TLS-failure reporting endpoint.
- GOOD: Present.
- MEDIUM: n/a
- BAD: n/a (not deliverability-relevant)
- ADVISORY: Missing — optional ops visibility.
- Severity: LOW (advisory) / INFO

### tlsrpt.multiple_records
- File: `audit/domain_health/checks/modern_records.py:222-237`
- Validates: One TLSRPT record.
- GOOD: Single.
- MEDIUM: n/a
- BAD: n/a
- ADVISORY: Multiple records.
- Severity: LOW (advisory, was HIGH) / INFO

### tlsrpt.syntax
- File: `audit/domain_health/checks/modern_records.py:240-256`
- Validates: `rua=` tag present (report destination).
- GOOD: rua= present.
- MEDIUM: n/a
- BAD: n/a
- ADVISORY: Missing rua=.
- Severity: LOW (advisory, was HIGH) / INFO

### bimi.published
- File: `audit/domain_health/checks/modern_records.py:259-274`
- Validates: TXT at `default._bimi.<domain>` (optional).
- GOOD: Found.
- MEDIUM: n/a
- BAD: Not present (optional — Gmail/Apple bonus only).
- Severity: INFO

### bimi.syntax
- File: `audit/domain_health/checks/modern_records.py:276-295`
- Validates: `l=` logo URL is HTTPS.
- GOOD: Has `l=https://...`.
- MEDIUM: Missing `l=` or non-HTTPS.
- BAD: n/a
- Severity: MEDIUM / INFO

---

## Domain Health — Blacklists / DBLs

### blacklist.sender_ip_extraction
- File: `audit/domain_health/checks/blacklist.py:265-288`
- Validates: Sender IP recoverable from Received chain.
- GOOD: IP extracted.
- MEDIUM: n/a
- BAD: No public sender IP (ARC-rewritten / forwarded).
- Severity: INFO

### blacklist.{label} (24 IP RBL lists)
- File: `audit/domain_health/checks/blacklist.py:185-262`
- Validates: Sender IP not listed on RBL (Spamhaus ZEN, Spamcop, Barracuda, CBL, UCEPROTECT L1/L2/L3, Mailspike, PSBL, etc.).
- GOOD: NXDOMAIN (not listed).
- MEDIUM: n/a
- BAD: Non-sentinel A record (IP listed).
- Severity: HIGH / MEDIUM / LOW (per list tier)

### sender_dbl.{label} (8 domain DBLs)
- File: `audit/domain_health/checks/sender_dbl.py:31-67`
- Validates: From-domain apex not on Spamhaus DBL, SURBL, URIBL, ivmURI, Nordspam DBL, SEM FRESH/URI/URIRED.
- GOOD: No listings.
- MEDIUM: n/a
- BAD: Apex listed → hard reject by major receivers.
- Severity: CRITICAL

### url_reputation.{label} (8 DBLs per body link)
- File: `audit/domain_health/checks/url_reputation.py:123-156`
- Validates: Every body-link domain not on DBLs.
- GOOD: No hits.
- MEDIUM: n/a
- BAD: Linked domain listed → 554 5.7.1 (SURBL) / 550 5.7.350 NDRs.
- Severity: HIGH / MEDIUM (per list)

---

## Domain Health — SMTP Probe (`audit/domain_health/checks/smtp_probe.py`)

> **Scope note:** This module probes the **inbound** MX server for shape sanity + open-relay safety. Inbound-MX operational metrics (connect time, banner readability, STARTTLS support) do **not** affect outbound deliverability — they were removed in the May 2026 restructure. The PTR / FCrDNS check that actually matters lives in `sending_ip_dns.py` and operates on the **sending IP extracted from Received headers**, not the MX IP.

### smtp.dns_resolution
- File: `audit/domain_health/checks/smtp_probe.py:88-104`
- Validates: MX records exist (needed for bounces and DMARC reports).
- GOOD: Present.
- MEDIUM: n/a
- BAD: None.
- Severity: HIGH / INFO

### smtp.null_mx
- File: `audit/domain_health/checks/smtp_probe.py:106-118`
- Validates: MX is not RFC 7505 null ("." — domain accepts no mail).
- GOOD: Not null.
- MEDIUM: n/a
- BAD: n/a
- Severity: INFO

### smtp.mx_bare_ip
- File: `audit/domain_health/checks/smtp_probe.py:142-160`
- Validates: MX target is a hostname (not a bare IP literal).
- GOOD: Hostname.
- MEDIUM: n/a
- BAD: Bare IP literal (RFC 1035/5321 violation; strict receivers reject).
- Severity: HIGH / INFO

### smtp.mx_cname_violation
- File: `audit/domain_health/checks/smtp_probe.py:162-182`
- Validates: MX target is not a CNAME (RFC 2181 §10.3).
- GOOD: Not CNAME.
- MEDIUM: Target is CNAME.
- BAD: n/a
- Severity: MEDIUM / INFO

### smtp.open_relay
- File: `audit/domain_health/checks/smtp_probe.py:184-218`
- Validates: MX rejects off-domain RCPT TO (single MAIL FROM / RCPT TO / RSET, no DATA sent).
- GOOD: Rejects (or inconclusive).
- MEDIUM: n/a
- BAD: Accepts → open relay → massive reputation hit.
- Severity: CRITICAL / INFO

### REMOVED from smtp_probe (was misleading)
> `smtp.connect`, `smtp.transaction_time`, `smtp.banner` — inbound-MX operational metrics, not deliverability signals.
> `smtp.tls` (STARTTLS on inbound MX) — measures whether you can **receive** TLS, not whether you **send** TLS. Misleading.
> `smtp.reverse_dns_resolution`, `smtp.reverse_dns_mismatch`, `smtp.banner_vs_ptr` — these probed the MX IP, but Gmail/MS require PTR on the **sending IP**. Moved to `sending_ip_dns.py` against the Received-extracted IP.

---

## Domain Health — Sending IP DNS (`audit/domain_health/checks/sending_ip_dns.py`)

> **Scope note:** This is the deliverability-relevant PTR check. Sending IP = IP extracted from Received headers (same logic as the RBL scan). For ESP senders (SendGrid / Mailchimp / Brevo / Klaviyo / etc.), failures are demoted to INFO — the marketer can't republish DNS on a shared ESP outbound IP.

### sending_ip.extraction
- File: `audit/domain_health/checks/sending_ip_dns.py:33-52`
- Validates: Sending IP recoverable from Received chain.
- GOOD: Public IPv4 extracted.
- MEDIUM: n/a
- BAD: No public sending IP (ARC-rewritten / forwarded mail).
- Severity: INFO (informational either way)

### sending_ip.ptr_resolves
- File: `audit/domain_health/checks/sending_ip_dns.py:54-83`
- Validates: PTR record exists for the actual sending IP. Gmail / Microsoft require this.
- GOOD: PTR resolves.
- MEDIUM: n/a
- BAD: No PTR → hard deliverability hit.
- Severity: HIGH / INFO (demoted to INFO when sending IP belongs to a known ESP)

### sending_ip.fcrdns
- File: `audit/domain_health/checks/sending_ip_dns.py:85-114`
- Validates: PTR hostname forward-resolves back to the same sending IP (Forward-Confirmed reverse DNS). Strict Gmail / Microsoft requirement.
- GOOD: PTR round-trips to original IP.
- MEDIUM: n/a
- BAD: PTR resolves to a different IP, or PTR has no A record.
- Severity: HIGH / INFO (demoted to INFO when sending IP belongs to a known ESP)

---

## Domain Health — Web Server — REMOVED

> Previously: `http.connect`, `https.certificate_check`, `https.certificate_expiration` (`audit/domain_health/checks/web_server.py`).
>
> **Why removed:** Apex website reachability and TLS cert state have zero impact on outbound email deliverability. Gmail / Yahoo / Microsoft do not inspect the sender's apex web server when scoring outbound mail. The web cert only matters indirectly when a body **link** points to the domain — and that path is already covered by `url_reputation.*` (link-domain DBL scan) and `content.anchor_href_mismatch`.
>
> If you want apex / linked-URL cert validation in the future, that belongs in a body-link health module — not in the deliverability score.

---

## Email Auth (header-level) (`audit/checks/auth.py`)

### auth.authentication_results
- File: `audit/checks/auth.py:22-31`
- Validates: `Authentication-Results` header present.
- GOOD: Present.
- MEDIUM: n/a
- BAD: Missing / stripped.
- Severity: HIGH / INFO

### auth.spf
- File: `audit/checks/auth.py:39-56`
- Validates: SPF verdict from receiver.
- GOOD: `spf=pass`.
- MEDIUM: n/a
- BAD: fail / softfail / neutral / none.
- Severity: HIGH / INFO

### auth.dkim
- File: `audit/checks/auth.py:39-56`
- Validates: DKIM verdict from receiver.
- GOOD: `dkim=pass`.
- MEDIUM: n/a
- BAD: fail / neutral / none.
- Severity: HIGH / INFO

### auth.dmarc
- File: `audit/checks/auth.py:39-56`
- Validates: DMARC verdict from receiver.
- GOOD: `dmarc=pass`.
- MEDIUM: n/a
- BAD: fail / softfail / none.
- Severity: CRITICAL (fail/softfail) / HIGH (missing) / INFO

### auth.arc
- File: `audit/checks/auth.py:58-68`
- Validates: ARC verdict.
- GOOD: `arc=pass`.
- MEDIUM: n/a
- BAD: fail / none / missing.
- Severity: INFO (informational)

### auth.bimi
- File: `audit/checks/auth.py:58-68`
- Validates: BIMI verdict.
- GOOD: `bimi=pass`.
- MEDIUM: n/a
- BAD: fail / none / missing.
- Severity: INFO

### auth.dmarc_policy_strength
- File: `audit/checks/auth.py:79-104`
- Validates: Receiver-reported `p=` from Authentication-Results.
- GOOD: quarantine / reject.
- MEDIUM: n/a
- BAD: `p=none`.
- Severity: LOW / INFO

---

## Email Auth — Alignment (`audit/checks/alignment.py`)

### auth.dmarc_alignment_dkim
- File: `audit/checks/alignment.py:105-142`
- Validates: DKIM `d=` registrable domain aligns with From org-domain (relaxed).
- GOOD: Aligned.
- MEDIUM: No DKIM-Signature header.
- BAD: Misaligned.
- Severity: HIGH (fail) / MEDIUM (missing) / INFO

### auth.dmarc_alignment_spf
- File: `audit/checks/alignment.py:144-182`
- Validates: Return-Path registrable domain aligns with From org-domain.
- GOOD: Aligned.
- MEDIUM: Differs or Return-Path missing (forwarded mail).
- BAD: n/a
- Severity: MEDIUM (fail) / LOW (missing) / INFO

### auth.dmarc_alignment_overall
- File: `audit/checks/alignment.py:184-217`
- Validates: At least one of SPF or DKIM aligns.
- GOOD: ≥1 aligns.
- MEDIUM: n/a
- BAD: Neither aligns → Gmail 5.7.26 / Microsoft 5.7.509.
- Severity: CRITICAL / INFO

### auth.reply_to_alignment
- File: `audit/checks/alignment.py:233-260`
- Validates: Reply-To domain matches From org-domain.
- GOOD: Aligned or no Reply-To.
- MEDIUM: n/a
- BAD: Reply-To differs (phishing signal).
- Severity: MEDIUM / INFO

### auth.reply_to_monitored
- File: `audit/checks/alignment.py:262-296`
- Validates: Effective reply address (Reply-To if present, else From) is not a `noreply@` / `donotreply@` / `do-not-reply@` mailbox. Microsoft sender guidance: From / Reply-To should be valid, reflect the true sending domain, and be able to receive replies.
- GOOD: Local-part is not in unmonitored set.
- MEDIUM: n/a
- BAD: n/a
- ADVISORY: Local-part is `noreply` / `no-reply` / `no_reply` / `donotreply` / `do-not-reply` / `do_not_reply` / `donot-reply` / `no.reply` / `do.not.reply`. Reduces two-way engagement; engagement is a deliverability factor.
- Severity: LOW (advisory) / INFO

---

## Email Auth — TLS Transport (`audit/checks/tls_transport.py`)

### auth.tls_transport
- File: `audit/checks/tls_transport.py`
- Validates: Last external SMTP hop (the handoff from external sender to receiver, located by walking the Received chain oldest-first for the first public-IPv4 hop — same logic as the RBL sender-IP extractor) used TLS. RFC 3848 markers: `with ESMTPS` / `STARTTLS` / `(version=TLS…)` / `using TLSv…`. Mandatory per Gmail sender requirements (all senders, 2024+) and Microsoft bulk sender requirements (May 2025+).
- GOOD: Last external hop Received header contains an ESMTPS / STARTTLS / TLS annotation.
- MEDIUM: n/a
- BAD: Last external hop is plain SMTP (no TLS marker) → Gmail / MS bulk-reject.
- Severity: HIGH / INFO
- Notes: Demoted to INFO when sending IP belongs to a high-confidence ESP profile (Mailchimp / Brevo / Klaviyo / SendGrid / Mailgun / etc.). Every major ESP submits over TLS as hard policy; missing marker in that case is a header-sanitization artifact at the relay, not an actual plain-text send. Also emits INFO with `passed=False` (informational only) when the Received chain is missing or no public-IPv4 hop can be located (forwarded / ARC-rewritten mail).

---

## Headers Hygiene (`audit/checks/header_hygiene.py`)

### headers.required_headers
- File: `audit/checks/header_hygiene.py:60-79`
- Validates: RFC 5322 required headers (From, To, Date, Subject, Message-ID).
- GOOD: All present.
- MEDIUM: n/a
- BAD: One or more missing (~1.5 spam-points each).
- Severity: HIGH / INFO

### headers.duplicate_headers
- File: `audit/checks/header_hygiene.py:81-100`
- Validates: No duplicate single-instance headers.
- GOOD: No dupes.
- MEDIUM: n/a
- BAD: Duplicate From / To / Subject / Date / Message-ID / Reply-To.
- Severity: HIGH / INFO

### headers.date_sanity
- File: `audit/checks/header_hygiene.py:102-154`
- Validates: Date header parseable + within 7 days of receive time.
- GOOD: Valid + within tolerance.
- MEDIUM: Unparseable or drift >6 h (SpamAssassin DATE_IN_*).
- BAD: n/a
- Severity: MEDIUM / INFO

### headers.message_id
- File: `audit/checks/header_hygiene.py:156-182`
- Validates: Message-ID well-formed `<local@domain>`.
- GOOD: Well-formed.
- MEDIUM: Missing or malformed.
- BAD: n/a
- Severity: MEDIUM (malformed) / LOW (missing) / INFO

---

## Bulk Compliance / Unsubscribe (`audit/checks/unsubscribe.py`, `unsubscribe_live.py`)

### content.list_unsubscribe_header
- File: `audit/checks/unsubscribe.py:88-122`
- Validates: `List-Unsubscribe` header on bulk mail.
- GOOD: Present (or not bulk).
- MEDIUM: n/a
- BAD: Missing on bulk → Gmail/Yahoo/Microsoft bulk-reject (2024).
- Severity: CRITICAL / INFO

### content.list_unsubscribe_post
- File: `audit/checks/unsubscribe.py:124-155`
- Validates: `List-Unsubscribe-Post: List-Unsubscribe=One-Click` (RFC 8058).
- GOOD: Present with token.
- MEDIUM: n/a
- BAD: Missing on bulk.
- Severity: CRITICAL / INFO

### content.unsubscribe_link_body
- File: `audit/checks/unsubscribe.py:162-182`
- Validates: Visible unsubscribe link in HTML body.
- GOOD: Link present.
- MEDIUM: Missing (required by Gmail/Yahoo sender guidelines).
- BAD: n/a
- Severity: MEDIUM / INFO

### render.unsub_clipped
- File: `audit/checks/unsubscribe.py:183-201`
- Validates: Unsub link before Gmail 102 KB clip.
- GOOD: At/before 102 KB.
- MEDIUM: n/a
- BAD: Past clip → Gmail hides it → users hit Spam.
- Severity: CRITICAL

### headers.precedence_bulk
- File: `audit/checks/unsubscribe.py:90-118`
- Validates: Bulk-shaped mail (detected via List-ID / Feedback-ID / campaign-id headers) also declares itself with `Precedence: bulk`. Skipped on non-bulk and when bulk was inferred *only* from this header (tautology).
- GOOD: `Precedence: bulk` present.
- MEDIUM: n/a
- BAD: n/a
- ADVISORY: Bulk-shaped mail without the header. SpamAssassin and several legacy filters give a small negative weight. Easy fix at the ESP.
- Severity: LOW (advisory) / INFO

### content.list_unsub_live_probe
- File: `audit/checks/unsubscribe_live.py:78-150`
- Validates: One-Click endpoint reachable (opt-in live probe).
- GOOD: POST → 2xx.
- MEDIUM: Other error / inconclusive.
- BAD: 4xx (401/403/404/405/410).
- Severity: HIGH (4xx) / MEDIUM (other) / INFO

### headers.feedback_id (`audit/checks/observability.py:37-64`)
- Validates: `Feedback-ID` header on bulk mail (Postmaster Tools visibility).
- GOOD: Present.
- MEDIUM: n/a
- BAD: Missing on bulk → no complaint attribution.
- Severity: INFO (currently informational)

---

## Body / Content — Size (`audit/checks/size.py`)

### size.html_present
- File: `audit/checks/size.py:14-22`
- Validates: HTML body exists.
- GOOD: Present.
- MEDIUM: n/a
- BAD: No text/html part.
- Severity: MEDIUM

### size.html_bytes
- File: `audit/checks/size.py:24-52`
- Validates: HTML body byte size.
- GOOD: ≤90 KB.
- MEDIUM: 90–102 KB.
- BAD: >102 KB (Gmail clip threshold).
- Severity: CRITICAL (>102) / HIGH (>90) / INFO

---

## Body / Content — Subject (`audit/checks/subject.py`)

### content.subject_present
- File: `audit/checks/subject.py:17-37`
- Validates: Subject header non-empty.
- GOOD: Has content.
- MEDIUM: n/a
- BAD: Missing or empty (Gmail/Yahoo/Outlook spam trigger).
- Severity: HIGH / INFO

---

## Body / Content — Composition (`audit/checks/body_composition.py`)

### content.plain_text_alternative
- File: `audit/checks/body_composition.py:27-50`
- Validates: text/plain alternative present, ≥100 chars.
- GOOD: Present + ≥100 chars.
- MEDIUM: Missing or <100 chars.
- BAD: n/a
- Severity: MEDIUM / INFO

### content.image_text_ratio
- File: `audit/checks/body_composition.py:52-92`
- Validates: Image-to-text ratio.
- GOOD: Visible text ≥500 chars OR ≤3 images.
- MEDIUM: n/a
- BAD: <500 chars AND >3 images (image-only email).
- Severity: HIGH / INFO

---

## Body / Content — Links (`audit/checks/link_quality.py`)

### content.url_shortener
- File: `audit/checks/link_quality.py:124-146`
- Validates: No URL shorteners (bit.ly, t.co, tinyurl, etc.).
- GOOD: None.
- MEDIUM: n/a
- BAD: Shortener present.
- Severity: MEDIUM / INFO

### content.anchor_href_mismatch
- File: `audit/checks/link_quality.py:148-169`
- Validates: Anchor visible text domain matches href domain.
- GOOD: All match.
- MEDIUM: n/a
- BAD: Mismatch → classic phishing shape.
- Severity: HIGH / INFO

---

## Body / Content — Attachments (`audit/checks/attachment_risk.py`)

### content.attachment_executable
- File: `audit/checks/attachment_risk.py:103-114`
- Validates: No `.exe / .scr / .bat / .cmd`.
- GOOD: None.
- MEDIUM: n/a
- BAD: Executable attached → Gmail / Defender quarantine.
- Severity: CRITICAL

### content.attachment_archive_risk
- File: `audit/checks/attachment_risk.py:116-127`
- Validates: No `.iso / .img / .7z / .rar / .cab`.
- GOOD: None.
- MEDIUM: n/a
- BAD: Bypasses Mark-of-the-Web.
- Severity: HIGH

### content.attachment_html_lure
- File: `audit/checks/attachment_risk.py:129-140`
- Validates: No `.html / .htm / .shtml` attachments.
- GOOD: None.
- MEDIUM: n/a
- BAD: HTML attach → #1 phishing carrier 2024–26.
- Severity: HIGH

### content.attachment_macro_doc
- File: `audit/checks/attachment_risk.py:142-152`
- Validates: No macro-enabled Office (`.docm / .xlsm / .pptm / .xlsb`).
- GOOD: None.
- MEDIUM: n/a
- BAD: Macro doc → corporate filters quarantine.
- Severity: MEDIUM

---

## Body / Content — Adversarial

### content.hidden_css_salting (`audit/checks/hidden_css.py:113-213`)
- Validates: No hidden-text salting (`display:none`, `opacity:0`, `text-indent:-9999px`).
- GOOD: None.
- MEDIUM: n/a
- BAD: Hidden patterns (ESP chrome demoted INFO; prompt-injection CRITICAL).
- Severity: CRITICAL (adversarial) / HIGH (user content) / INFO (ESP chrome)

### content.homoglyphs (`audit/checks/homoglyph.py:18-63`)
- Validates: No lookalike Unicode in subject / body / link hostnames.
- GOOD: None.
- MEDIUM: n/a
- BAD: Homoglyph found.
- Severity: CRITICAL (link host) / HIGH (subject/body) / INFO

### content.bidi_override (`audit/checks/invisible_chars.py:64-116`)
- Validates: No U+202D / U+202E bidi overrides.
- GOOD: None.
- MEDIUM: n/a
- BAD: Bidi override (canonical prompt-injection).
- Severity: CRITICAL / INFO

### content.zero_width (`audit/checks/invisible_chars.py:118-164`)
- Validates: No zero-width / invisible chars.
- GOOD: None.
- MEDIUM: n/a
- BAD: Zero-width detected (ESP chrome demoted INFO).
- Severity: HIGH (user content) / INFO (ESP chrome)

---

## Body / Content — Template Quality (`audit/checks/template_quality.py`)

### content.empty_href
- File: `audit/checks/template_quality.py:85-120`
- Validates: All anchors have non-empty `href`.
- GOOD: All have href.
- MEDIUM: n/a
- BAD: Empty href → clickable button to nowhere (phishing shape).
- Severity: HIGH / INFO

### content.merge_tag_unfilled
- File: `audit/checks/template_quality.py:123-161`
- Validates: No unrendered Mustache / Brevo / Jinja placeholders or empty greetings.
- GOOD: All merge tags resolved.
- MEDIUM: n/a
- BAD: Unrendered placeholder or "Hi ,".
- Severity: HIGH / INFO

### content.body_visible_text_min
- File: `audit/checks/template_quality.py:164-197`
- Validates: ≥100 chars visible text on bulk.
- GOOD: ≥100 chars.
- MEDIUM: <100 chars on bulk.
- BAD: n/a
- Severity: MEDIUM (bulk) / LOW (non-bulk) / INFO

### headers.template_test_send
- File: `audit/checks/template_quality.py:200-226`
- Validates: No ESP test-send headers (`X-Mailin-Type`, `X-Test`, `X-Preview-Send`).
- GOOD: None.
- MEDIUM: n/a
- BAD: Test-send header on production send.
- Severity: HIGH / INFO

---

## Body / Content — Copywriting (`audit/checks/copywriting.py`)

### copywriting.subject_heuristics
- File: `audit/checks/copywriting.py:86-122`
- Validates: Subject length / case / emoji / etc.
- GOOD: Scores well.
- MEDIUM: n/a
- BAD: Spam-trigger patterns (ALL CAPS, length, emoji bursts).
- Severity: MEDIUM / HIGH / LOW (per rule)

### copywriting.spam_triggers
- File: `audit/checks/copywriting.py:86-122`
- Validates: No spam-trigger substrings in subject / preview / body.
- GOOD: None.
- MEDIUM: n/a
- BAD: Trigger keywords found.
- Severity: MEDIUM / HIGH

### copywriting.compound_signal
- File: `audit/checks/copywriting.py:86-122`
- Validates: Compound promotional signal count.
- GOOD: <3 categories.
- MEDIUM: 3–4 categories.
- BAD: 5+ categories (stacked = deliverability killer).
- Severity: CRITICAL (5+) / HIGH (4) / MEDIUM (3) / INFO

### copywriting.body_length
- File: `audit/checks/copywriting.py:86-122`
- Validates: Body word count in range.
- GOOD: In range.
- MEDIUM: n/a
- BAD: Too long / too short.
- Severity: MEDIUM / HIGH

### copywriting.links
- File: `audit/checks/copywriting.py:86-122`
- Validates: Link count + destinations (Drive-only detection).
- GOOD: Sensible link budget.
- MEDIUM: n/a
- BAD: Too many or Drive-only.
- Severity: MEDIUM / HIGH

### copywriting.body_shouting
- File: `audit/checks/copywriting.py:86-122`
- Validates: No excessive ALL CAPS / `!` / `?`.
- GOOD: Normal emphasis.
- MEDIUM: n/a
- BAD: Excessive shouting.
- Severity: MEDIUM / HIGH

### copywriting.body_emoji
- File: `audit/checks/copywriting.py:86-122`
- Validates: Emoji count moderate.
- GOOD: Moderate.
- MEDIUM: n/a
- BAD: Too many.
- Severity: MEDIUM / INFO

### copywriting.body_newsletter_word
- File: `audit/checks/copywriting.py:86-122`
- Validates: Body doesn't refer to itself as "newsletter".
- GOOD: Absent.
- MEDIUM: n/a
- BAD: Word present.
- Severity: MEDIUM / INFO

---

## Microsoft EOP (`audit/checks/microsoft_eop.py`)

### microsoft_eop.transit
- File: `audit/checks/microsoft_eop.py:93-107`
- Validates: M365/Outlook EOP headers present.
- GOOD: EOP headers detected.
- MEDIUM: n/a
- BAD: Not transited (no EOP signal).
- Severity: INFO

### microsoft_eop.scl
- File: `audit/checks/microsoft_eop.py:110-125`
- Validates: SCL (Spam Confidence Level).
- GOOD: 0–1 (not spam).
- MEDIUM: 5–6 (spam).
- BAD: 7–9 (high-confidence; quarantined on Standard/Strict).
- Severity: HIGH (7-9) / MEDIUM (5-6) / INFO

### microsoft_eop.sfv
- File: `audit/checks/microsoft_eop.py:128-138`
- Validates: SFV (Spam Filter Verdict).
- GOOD: NSPM / SKN / SKS / SKA / SKI / SKQ / SFE.
- MEDIUM: n/a
- BAD: SPM / SKB / BLK / PHSH / AAD.
- Severity: HIGH (spam/phish) / INFO

### microsoft_eop.bcl
- File: `audit/checks/microsoft_eop.py:141-156`
- Validates: BCL (Bulk Complaint Level).
- GOOD: 0–3.
- MEDIUM: 8–9 (high complaint).
- BAD: n/a
- Severity: MEDIUM (8-9) / LOW (4-7) / INFO

### microsoft_eop.compauth
- File: `audit/checks/microsoft_eop.py:158-176`
- Validates: compauth verdict.
- GOOD: pass.
- MEDIUM: softpass / none.
- BAD: fail.
- Severity: HIGH (fail) / LOW (softpass/none) / INFO

---

## Drift (across multiple sends)

### drift.d01_dmarc_regression (`audit/drift/d01_dmarc_regression.py:23-54`)
- Validates: DMARC has not regressed from passing history.
- GOOD: DMARC=pass or no regression.
- MEDIUM: Mixed/sparse history + current fail/softfail.
- BAD: ≥3 prior passes + current fail/softfail.
- Severity: CRITICAL (clear regression) / HIGH (mixed) / INFO

### drift.d03_auth_flip (`audit/drift/d03_auth_flip.py:22-72`)
- Validates: SPF & DKIM pass rates haven't flipped from ≥90 % history.
- GOOD: Stable / improved.
- MEDIUM: n/a
- BAD: Either flipped (or both).
- Severity: CRITICAL (both) / HIGH (one) / INFO

### drift.d04_dmarc_policy_downgrade (`audit/drift/d04_dmarc_policy_downgrade.py:29-74`)
- Validates: DMARC policy hasn't downgraded over 30 days.
- GOOD: Equal or stronger than historical max.
- MEDIUM: n/a
- BAD: Downgrade (reject → quarantine, quarantine → none).
- Severity: HIGH / INFO

### drift.d08_list_unsub_regression (`audit/drift/d08_list_unsub_regression.py:23-88`)
- Validates: RFC 8058 compliance hasn't regressed.
- GOOD: Stable or improved.
- MEDIUM: Lost HTTPS unsub (still has mailto).
- BAD: Lost List-Unsubscribe or One-Click vs ≥80 % history.
- Severity: HIGH / MEDIUM / INFO

### drift.d10_display_name_rotation (`audit/drift/d10_display_name_rotation.py:39-167`)
- Validates: Display-name doesn't rotate / spoof.
- GOOD: Stable; churn <30 %; no spoof.
- MEDIUM: New name vs 3+ historical; churn 30–50 %.
- BAD: Churn >50 % OR friendly-from spoof.
- Severity: HIGH (spoof / >50 %) / MEDIUM (new / 30–50 %) / INFO

### drift.d11_reply_to_divergence (`audit/drift/d11_reply_to_divergence.py:37-84`)
- Validates: Bulk Reply-To not diverged from prior history.
- GOOD: Aligned or in history.
- MEDIUM: n/a
- BAD: New freemail Reply-To OR new domain not in history (VEC pattern).
- Severity: CRITICAL (freemail) / HIGH (new domain) / INFO

---

## Runner / Orchestration (meta-findings)

> These are emitted by the audit orchestrator, not individual check modules. They surface state about *what ran* (or didn't) and a couple of cross-cutting signals.

### domain_health.sender_extraction
- File: `audit/domain_health/runner.py:112-117`
- Validates: From: address parseable into a registrable domain.
- GOOD: Domain extracted.
- MEDIUM: n/a
- BAD: From: empty / malformed → entire domain-health phase skipped.
- Severity: INFO (informational; downstream checks short-circuit)

### blacklist.skipped_esp
- File: `audit/domain_health/runner.py:131-142`
- Validates: Suppression notice — sending IP belongs to a high-confidence ESP (Mailchimp / Brevo / Klaviyo / SendGrid / etc.) → RBL fan-out skipped because ESP shared IPs always have *some* RBL listing.
- GOOD: n/a (always passed=True, informational)
- MEDIUM: n/a
- BAD: n/a
- Severity: INFO

### smtp.managed_operator
- File: `audit/domain_health/runner.py:178-189`
- Validates: Suppression notice — MX records resolve under M365 / Google Workspace / Mimecast / Proofpoint / Fastmail / Zoho / Yahoo → SMTP-side findings demoted to INFO because the operator owns the infrastructure.
- GOOD: n/a (always passed=True, informational)
- MEDIUM: n/a
- BAD: n/a
- Severity: INFO

### delivery.spam_folder
- File: `audit/runner.py:138-152`
- Validates: Recipient (Gmail in current pipeline) did not route this message to the Spam folder.
- GOOD: Inbox (or any non-Spam label).
- MEDIUM: n/a
- BAD: Message landed in Spam → score capped at `SPAM_SCORE_CAP` (hard gate).
- Severity: HIGH (hard_gate=True) / not emitted on pass

---

## Coverage status

This rubric is comprehensive for every check ID emitted by the current codebase (verified by cross-referencing `grep "check="` against `### <name>` headings). When adding a new check module, append its entry under the matching section header and re-run the audit so this stays canonical.
