"""SPF record checks against the sender's published TXT.

Mirrors the mxtoolbox SPF tier:
  - Record Published / Multiple Records / Syntax Check
  - Included Lookups (RFC 7208 §4.6.4 caps at 10) / Recursive Loop
  - Type PTR Check / Modifier / Record Deprecated / Null Value
  - Contains characters after ALL / Duplicate Include / Redirect Evaluation
  - Void Lookups (RFC 7208 §4.6.4 caps at 2)

We don't actually evaluate SPF (no caller IP); we audit the *record's*
shape and reachability. Pass/fail at evaluation time is already covered
by `audit.domain.auth.results.spf` from the receiver's Authentication-Results.
"""

from __future__ import annotations

import re

from ...report import Finding
from ...severity import Severity
from ..dns_client import DnsAnswer, query

CHECK_PREFIX = "spf_record"

_SPF_PREFIX_RX = re.compile(r"^\s*v\s*=\s*spf1\b", re.IGNORECASE)
_TOKEN_SPLIT_RX = re.compile(r"\s+")
_VALID_QUALIFIERS = ("+", "-", "~", "?")
_VALID_MECHS = (
    "all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists",
)
_VALID_MODIFIERS = ("redirect", "exp")

_LOOKUP_LIMIT = 10
_VOID_LIMIT = 2


def _parse_record(text: str) -> dict:
    """Light tokenizer. Returns shape used by every downstream check."""
    tokens = [t for t in _TOKEN_SPLIT_RX.split(text.strip()) if t]
    mechanisms: list[dict] = []
    modifiers: list[dict] = []
    for tok in tokens[1:]:  # skip v=spf1
        if "=" in tok and not tok.startswith(("ip4:", "ip6:", "include:", "exists:", "a:", "mx:")):
            name, _, val = tok.partition("=")
            modifiers.append({"name": name.lower(), "value": val})
            continue
        qualifier = "+"
        if tok and tok[0] in _VALID_QUALIFIERS:
            qualifier, tok = tok[0], tok[1:]
        mech, _, val = tok.partition(":")
        mechanisms.append({"qualifier": qualifier, "mechanism": mech.lower(), "value": val})
    return {"raw": text, "mechanisms": mechanisms, "modifiers": modifiers}


def _find_spf_record(ans: DnsAnswer) -> str | None:
    if not ans.ok:
        return None
    for r in ans.records:
        if _SPF_PREFIX_RX.match(r):
            return r
    return None


def _all_spf_records(ans: DnsAnswer) -> list[str]:
    if not ans.ok:
        return []
    return [r for r in ans.records if _SPF_PREFIX_RX.match(r)]


async def _count_lookups(parsed: dict, domain: str, depth: int = 0, seen: set | None = None) -> tuple[int, int, list[str]]:
    """Recursively count DNS-lookup mechanisms (RFC 7208 §4.6.4) and void
    responses. `seen` guards against include loops. Returns
    (lookup_count, void_count, errors)."""
    if seen is None:
        seen = set()
    if domain in seen or depth > 12:
        return (0, 0, ["recursive_loop" if domain in seen else "too_deep"])
    seen = seen | {domain}

    lookups = 0
    voids = 0
    errors: list[str] = []
    for m in parsed["mechanisms"]:
        mech = m["mechanism"]
        if mech in ("a", "mx", "ptr", "exists"):
            lookups += 1
            target = m["value"] or domain
            ans = await query(target, "A" if mech in ("a", "exists") else mech.upper())
            if ans.error in ("nxdomain", "no_answer"):
                voids += 1
        elif mech == "include":
            lookups += 1
            target = m["value"]
            if not target:
                errors.append("empty_include")
                continue
            inc = await query(target, "TXT")
            spf_record = _find_spf_record(inc)
            if spf_record is None:
                voids += 1
                continue
            sub = _parse_record(spf_record)
            sub_lookups, sub_voids, sub_errors = await _count_lookups(sub, target, depth + 1, seen)
            lookups += sub_lookups
            voids += sub_voids
            errors.extend(sub_errors)
    for mod in parsed["modifiers"]:
        if mod["name"] == "redirect":
            lookups += 1
            target = mod["value"]
            if target:
                redir = await query(target, "TXT")
                rec = _find_spf_record(redir)
                if rec is None:
                    voids += 1
                else:
                    sub = _parse_record(rec)
                    sub_lookups, sub_voids, sub_errors = await _count_lookups(sub, target, depth + 1, seen)
                    lookups += sub_lookups
                    voids += sub_voids
                    errors.extend(sub_errors)
    return lookups, voids, errors


async def run(domain: str) -> list[Finding]:
    findings: list[Finding] = []
    ans = await query(domain, "TXT")
    spf_records = _all_spf_records(ans)

    if not spf_records:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.published",
            severity=Severity.HIGH,
            passed=False,
            message=f"No SPF record published at {domain} (TXT v=spf1 ...).",
            details={"dns_error": ans.error, "lookup_ms": ans.elapsed_ms},
        ))
        return findings

    findings.append(Finding(
        check=f"{CHECK_PREFIX}.published",
        severity=Severity.INFO,
        passed=True,
        message=f"SPF record published at {domain}.",
        details={"record": spf_records[0][:200]},
    ))

    if len(spf_records) > 1:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.multiple_records",
            severity=Severity.HIGH,
            passed=False,
            message=(
                f"{len(spf_records)} SPF records found. RFC 7208 §3.2 forbids "
                "this; receivers will treat SPF as PermError."
            ),
            details={"count": len(spf_records)},
        ))
    else:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.multiple_records",
            severity=Severity.INFO,
            passed=True,
            message="Single SPF record.",
        ))

    primary = spf_records[0]
    parsed = _parse_record(primary)
    syntax_issues: list[str] = []
    saw_all = False
    after_all = False
    seen_includes: set[str] = set()
    duplicate_includes: list[str] = []
    has_ptr = False
    has_redirect = any(m["name"] == "redirect" for m in parsed["modifiers"])
    has_all = any(m["mechanism"] == "all" for m in parsed["mechanisms"])

    for m in parsed["mechanisms"]:
        if m["mechanism"] not in _VALID_MECHS:
            syntax_issues.append(f"unknown mechanism '{m['mechanism']}'")
        if m["mechanism"] == "ptr":
            has_ptr = True
        if m["mechanism"] == "all":
            saw_all = True
            continue
        if saw_all:
            after_all = True
        if m["mechanism"] == "include":
            v = (m["value"] or "").lower()
            if v in seen_includes:
                duplicate_includes.append(v)
            seen_includes.add(v)
    for mod in parsed["modifiers"]:
        if mod["name"] not in _VALID_MODIFIERS:
            syntax_issues.append(f"unknown modifier '{mod['name']}'")

    if syntax_issues:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.syntax",
            severity=Severity.HIGH,
            passed=False,
            message=f"SPF syntax issues: {'; '.join(syntax_issues[:5])}",
            details={"issues": syntax_issues},
        ))
    else:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.syntax",
            severity=Severity.INFO,
            passed=True,
            message="SPF syntax OK.",
        ))

    if after_all:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.chars_after_all",
            severity=Severity.MEDIUM,
            passed=False,
            message="Mechanisms appear after 'all'; receivers ignore them.",
        ))
    else:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.chars_after_all",
            severity=Severity.INFO,
            passed=True,
            message="Nothing after 'all'.",
        ))

    if duplicate_includes:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.duplicate_include",
            severity=Severity.LOW,
            passed=False,
            message=f"Duplicate include(s): {duplicate_includes[:5]}",
            details={"duplicates": duplicate_includes},
        ))
    else:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.duplicate_include",
            severity=Severity.INFO,
            passed=True,
            message="No duplicate includes.",
        ))

    if has_ptr:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.ptr_mechanism",
            severity=Severity.MEDIUM,
            passed=False,
            message=(
                "SPF uses the deprecated 'ptr' mechanism. RFC 7208 §5.5 says "
                "do not use; slow + unreliable."
            ),
        ))
    else:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.ptr_mechanism",
            severity=Severity.INFO,
            passed=True,
            message="No 'ptr' mechanism.",
        ))

    if has_redirect and has_all:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.redirect_with_all",
            severity=Severity.MEDIUM,
            passed=False,
            message=(
                "SPF has both 'redirect=' modifier and 'all' mechanism. "
                "'all' wins — redirect is ignored. Pick one."
            ),
        ))
    else:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.redirect_with_all",
            severity=Severity.INFO,
            passed=True,
            message="Redirect/all combination OK.",
        ))

    lookups, voids, recursion_errors = await _count_lookups(parsed, domain)
    if lookups > _LOOKUP_LIMIT:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.included_lookups",
            severity=Severity.HIGH,
            passed=False,
            message=(
                f"SPF requires {lookups} DNS lookups; RFC 7208 caps at "
                f"{_LOOKUP_LIMIT}. Receivers may PermError."
            ),
            details={"count": lookups, "limit": _LOOKUP_LIMIT},
        ))
    else:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.included_lookups",
            severity=Severity.INFO,
            passed=True,
            message=f"SPF lookup count {lookups} (≤ {_LOOKUP_LIMIT}).",
        ))

    if voids > _VOID_LIMIT:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.void_lookups",
            severity=Severity.MEDIUM,
            passed=False,
            message=(
                f"{voids} void DNS lookups (NXDOMAIN/no-answer). RFC 7208 "
                f"caps at {_VOID_LIMIT}; over the cap forces PermError."
            ),
            details={"count": voids, "limit": _VOID_LIMIT},
        ))
    else:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.void_lookups",
            severity=Severity.INFO,
            passed=True,
            message=f"Void lookups {voids} (≤ {_VOID_LIMIT}).",
        ))

    if "recursive_loop" in recursion_errors:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.recursive_loop",
            severity=Severity.HIGH,
            passed=False,
            message="SPF include chain has a recursive loop.",
        ))
    else:
        findings.append(Finding(
            check=f"{CHECK_PREFIX}.recursive_loop",
            severity=Severity.INFO,
            passed=True,
            message="No recursive include loop.",
        ))

    return findings
