"""Deterministic copy heuristics. No model call.

Each function takes plain text and returns a list of `Finding`. The audit
runner reaches them through `engine/copywriting/heuristics.py`, which maps
the legacy `copygen.` check prefix onto `copywriting.`.

Checks:
- Subject shape per variant: length, word count, Title Case, ALL CAPS,
  "!" and "?" counts, a "Re:" or "Fwd:" prefix, the word "newsletter",
  emoji count, and a "$" opener.
- Spam-trigger substring scan over subject, preview text, and body. The
  phrases load from `engine/context/spam_triggers.md`.
- Compound signal: how many distinct promotional categories the email hits.
  3 categories is MEDIUM, 4 is HIGH, 5 is CRITICAL. Stacked signals move
  the filter, not any single word.
- Body word count against a length target.
- Link count and destination sanity. A drive.google.com or docs.google.com
  link is HIGH.
- The word "newsletter" in the body.
- Emoji in the subject or body.
"""

from __future__ import annotations

import re
from pathlib import Path

from engine.prose import listed
from engine.report import Finding
from engine.severity import Severity

_SPAM_TRIGGERS_PATH = Path(__file__).resolve().parent / "context" / "spam_triggers.md"

_LENGTH_HINT_CAPS = {
    "short": 200,
    "medium": 300,
    "long": 450,
}
_ABSOLUTE_BODY_CEILING = 300

_URL_RX = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
_DRIVE_HOST_RX = re.compile(r"(drive|docs)\.google\.com", re.IGNORECASE)
_EMOJI_RX = re.compile(
    "["
    "\U0001f300-\U0001faff"  # symbols + emoji blocks
    "\U00002600-\U000027bf"  # misc symbols + dingbats
    "\U0001f000-\U0001f9ff"  # mahjong through symbols & pictographs
    "\U0001fa70-\U0001faff"  # more symbols
    "\U00002700-\U000027bf"  # dingbats
    "]",
    re.UNICODE,
)
_NEWSLETTER_RX = re.compile(r"\bnewsletter\b", re.IGNORECASE)

# The part of the composer a sender looks at, per internal field key.
_FIELD_NAMES = {
    "subject": "subject line",
    "preview": "preview text field",
    "body": "body",
}

# The promotional categories in spam_triggers.md, in words a sender uses. A
# category added to that file without a name here reads as its own label with
# the dashes removed, which rule 12 keeps out of text a user sees.
_CATEGORY_NAMES = {
    "urgency": "urgency",
    "fomo": "fear of missing out",
    "commerce-cta": "a hard sales call to action",
    "financial-promise": "a money promise",
    "generic-greeting": "a generic greeting",
}


def _category_names(slugs: list[str]) -> str:
    return listed(_CATEGORY_NAMES.get(s, s.replace("-", " ")) for s in slugs)


_LOGO_TOKEN_RX = re.compile(r"(\{logo\}|<img|<logo>|<table|<div)", re.IGNORECASE)


def _load_trigger_map() -> dict[str, list[str]]:
    """Parse spam_triggers.md → {category: [phrase, phrase, ...]}.

    Category headers look like `# ─── label ───`. Lines that start with `#`
    but don't contain `─` (box-drawing dash) are treated as free-form
    comments and do not change the current category. Non-blank, non-comment
    lines are phrases belonging to the current category.
    """
    result: dict[str, list[str]] = {}
    current = "uncategorised"
    if not _SPAM_TRIGGERS_PATH.exists():
        return result
    for raw_line in _SPAM_TRIGGERS_PATH.read_text().splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            if "─" not in stripped:
                continue  # regular comment, skip
            label = stripped.lstrip("#").strip().strip("─").strip()
            if label:
                current = label.lower()
            continue
        result.setdefault(current, []).append(stripped.lower())
    return result


def _check_subjects(subjects: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for i, subj in enumerate(subjects):
        subj = subj or ""
        issues: list[tuple[Severity, str]] = []
        # Several subject lines mean a draft carrying alternatives. With one, a
        # number in front of the sentence is noise, so the name carries it.
        name = (
            "The subject line" if len(subjects) == 1 else f"Subject line {i + 1} of {len(subjects)}"
        )

        if len(subj) > 50:
            issues.append(
                (
                    Severity.MEDIUM,
                    f"{name} is {len(subj)} characters long. Keep it to 50 or fewer, "
                    f"so an inbox does not cut off the end.",
                )
            )
        words = subj.split()
        if len(words) > 8:
            issues.append(
                (
                    Severity.LOW,
                    f"{name} is {len(words)} words. Keep it to 8 or fewer, because a "
                    f"reader scans only the first few.",
                )
            )

        alpha_words = [w for w in words if any(c.isalpha() for c in w)]
        if alpha_words:
            title_case = sum(1 for w in alpha_words if w[0].isupper() and not w.isupper())
            if title_case / len(alpha_words) >= 0.5 and len(alpha_words) >= 3:
                issues.append(
                    (
                        Severity.MEDIUM,
                        f"{name} is in Title Case. Use sentence case, with a capital "
                        f"on the first word only.",
                    )
                )

            all_caps = sum(1 for w in alpha_words if len(w) > 1 and w.isupper())
            if all_caps / len(alpha_words) > 0.3:
                issues.append(
                    (
                        Severity.HIGH,
                        f"{name} uses capitals for whole words. Write them in normal case.",
                    )
                )

        if subj.count("!") > 1:
            issues.append(
                (Severity.MEDIUM, f"{name} has more than one exclamation mark. Keep one at most.")
            )
        if subj.count("?") > 1:
            issues.append(
                (Severity.LOW, f"{name} has more than one question mark. Keep one at most.")
            )

        if re.match(r"^\s*(re|fwd|fw)\s*:", subj, re.IGNORECASE):
            issues.append(
                (
                    Severity.HIGH,
                    f"{name} starts with Re: or Fwd:, which tells the reader this is a "
                    f"reply when it is not. Remove it.",
                )
            )

        if _NEWSLETTER_RX.search(subj):
            issues.append(
                (
                    Severity.LOW,
                    f"{name} contains the word newsletter, which measures about 19 "
                    f"percent worse on open rate. Say what is inside the email instead.",
                )
            )

        if _EMOJI_RX.search(subj):
            count = len(_EMOJI_RX.findall(subj))
            if count > 1:
                issues.append((Severity.MEDIUM, f"{name} has {count} emoji. Keep one at most."))

        leading = subj.lstrip()
        if leading.startswith("$") or re.match(
            r"^\$?\s*\d+[\d,]*\s*(off|save|\$|%)", leading, re.IGNORECASE
        ):
            issues.append(
                (
                    Severity.MEDIUM,
                    f"{name} opens with a price. Lead with what the reader gets and "
                    f"put the number later.",
                )
            )

        for sev, msg in issues:
            findings.append(
                Finding(
                    check="copygen.subject_heuristics",
                    severity=sev,
                    passed=False,
                    message=msg,
                    details={"variant_index": i, "subject": subj},
                )
            )
    if not findings:
        findings.append(
            Finding(
                check="copygen.subject_heuristics",
                severity=Severity.INFO,
                passed=True,
                message=(
                    "Nothing to fix in the subject line."
                    if len(subjects) == 1
                    else f"Nothing to fix in any of the {len(subjects)} subject lines."
                ),
            )
        )
    return findings


def _check_spam_triggers(
    subject: str, preview: str, body: str, trigger_map: dict[str, list[str]]
) -> tuple[list[Finding], set[str]]:
    """Per-phrase findings + set of categories that fired (for compound score)."""
    findings: list[Finding] = []
    fired_categories: set[str] = set()
    fields = {"subject": subject, "preview": preview, "body": body}
    for category, phrases in trigger_map.items():
        for phrase in phrases:
            for field_name, text in fields.items():
                if phrase in (text or "").lower():
                    fired_categories.add(category)
                    sev = Severity.HIGH if category != "newsletter-word" else Severity.LOW
                    findings.append(
                        Finding(
                            check="copygen.spam_trigger",
                            severity=sev,
                            passed=False,
                            message=(
                                f'The {_FIELD_NAMES[field_name]} contains "{phrase}". '
                                f"Bulk filters score that wording, so say the same thing "
                                f"in plain words."
                            ),
                            details={
                                "phrase": phrase,
                                "category": category,
                                "field": field_name,
                            },
                        )
                    )
    if not findings:
        findings.append(
            Finding(
                check="copygen.spam_trigger",
                severity=Severity.INFO,
                passed=True,
                message=(
                    "No filter-triggering wording in the subject line, the preview "
                    "text or the body."
                ),
            )
        )
    return findings, fired_categories


def _check_compound_signal(fired_categories: set[str]) -> list[Finding]:
    # Formatting / newsletter-word are too noisy to count toward the
    # compound-promotional score on their own.
    promotional = {
        c for c in fired_categories if c not in ("formatting", "newsletter-word", "uncategorised")
    }
    n = len(promotional)
    if n <= 2:
        return [
            Finding(
                check="copygen.compound_signal",
                severity=Severity.INFO,
                passed=True,
                message=(
                    "The copy stacks no promotional language."
                    if n == 0
                    else f"The copy uses {_category_names(sorted(promotional))}, below "
                    f"the 3 kinds that count as a stack."
                ),
                details={"categories": sorted(promotional), "count": n},
            )
        ]
    if n == 3:
        sev = Severity.MEDIUM
    elif n == 4:
        sev = Severity.HIGH
    else:
        sev = Severity.CRITICAL
    return [
        Finding(
            check="copygen.compound_signal",
            severity=sev,
            passed=False,
            message=(
                f"The copy stacks {n} kinds of promotional language at once: "
                f"{_category_names(sorted(promotional))}. One kind on its own moves "
                f"little. Together they move the filter, so keep one and cut the rest."
            ),
            details={"categories": sorted(promotional), "count": n},
        )
    ]


def _check_body_length(body: str, length_hint: str) -> list[Finding]:
    word_count = len((body or "").split())
    cap = _LENGTH_HINT_CAPS.get(length_hint, 200)
    findings: list[Finding] = []
    if word_count > cap + (cap // 2):
        findings.append(
            Finding(
                check="copygen.body_length",
                severity=Severity.MEDIUM,
                passed=False,
                message=(
                    f"The body is {word_count} words. A {length_hint} email should run "
                    f"to about {cap}, so cut it back."
                ),
                details={"word_count": word_count, "cap": cap, "length_hint": length_hint},
            )
        )
    if length_hint == "short" and word_count > _ABSOLUTE_BODY_CEILING:
        findings.append(
            Finding(
                check="copygen.body_length",
                severity=Severity.HIGH,
                passed=False,
                message=(
                    f"The body is {word_count} words. A short email that runs past 300 "
                    f"words is no longer short, so split it or cut it."
                ),
                details={"word_count": word_count},
            )
        )
    if not findings:
        findings.append(
            Finding(
                check="copygen.body_length",
                severity=Severity.INFO,
                passed=True,
                message=(
                    f"The body is {word_count} words, inside the {cap} a {length_hint} "
                    f"email should run."
                ),
                details={"word_count": word_count, "cap": cap, "length_hint": length_hint},
            )
        )
    return findings


def _check_links(body: str) -> list[Finding]:
    findings: list[Finding] = []
    urls = _URL_RX.findall(body or "")
    word_count = len((body or "").split())
    # Ratio rule: ~1 link per 125 words for newsletter bodies. Floor at 2
    # so short drafts can carry a CTA + an unsubscribe link without
    # tripping the check. Modern filters care about per-word link density,
    # not an absolute cap.
    link_budget = max(2, word_count // 125)
    if len(urls) > link_budget:
        findings.append(
            Finding(
                check="copygen.link_count",
                severity=Severity.MEDIUM,
                passed=False,
                message=(
                    f"The body has {len(urls)} links in {word_count} words. Filters "
                    f"read links against the word count, and this length carries "
                    f"{link_budget}, so remove {len(urls) - link_budget}."
                ),
                details={
                    "count": len(urls),
                    "urls": urls[:5],
                    "word_count": word_count,
                    "link_budget": link_budget,
                },
            )
        )
    has_drive = False
    for url in urls:
        if _DRIVE_HOST_RX.search(url):
            has_drive = True
            findings.append(
                Finding(
                    check="copygen.drive_link",
                    severity=Severity.HIGH,
                    passed=False,
                    message=(
                        f"The body links to Google Drive at {url}. Filters treat a "
                        f"shared-document link as high risk, so host the file on your "
                        f"own domain or attach it."
                    ),
                    details={"url": url},
                )
            )
    if not any(f.check == "copygen.link_count" for f in findings):
        findings.append(
            Finding(
                check="copygen.link_count",
                severity=Severity.INFO,
                passed=True,
                message=(
                    f"The body has {len(urls)} links in {word_count} words, inside the "
                    f"{link_budget} this length carries."
                ),
                details={
                    "count": len(urls),
                    "word_count": word_count,
                    "link_budget": link_budget,
                },
            )
        )
    if not has_drive:
        findings.append(
            Finding(
                check="copygen.drive_link",
                severity=Severity.INFO,
                passed=True,
                message="No Google Drive or Google Docs links in the body.",
            )
        )
    return findings


def _check_body_shouting(body: str) -> list[Finding]:
    """Flag body lines that shout (ALL-CAPS runs) or stack exclamation marks.

    Triggers:
     - Any body line where >= 50% of NON-ACRONYM alpha words are ALL-CAPS
       (line must have ≥ 3 non-acronym alpha words) → MEDIUM.
     - Any body line containing 3+ consecutive ALL-CAPS NON-ACRONYM words
       anywhere within it ("AND BUY THIS COURSE!" inside a longer sentence)
       → MEDIUM.
     - Any body line with `!!` or more → MEDIUM.
     - Total `!` count in body > 3 → LOW.

    Acronym carve-out: tokens that are ALL-CAPS AND ≤ 4 chars are treated
    as acronyms (ATSC, PSIP, FCC, NBC, ROI), not shouting. Otherwise table-
    header rows full of technical acronyms get mis-flagged as shouting.
    """
    findings: list[Finding] = []
    body = body or ""
    shouting_lines: list[str] = []
    multi_bang_lines: list[str] = []

    def _is_acronym(w: str) -> bool:
        # Short all-caps tokens like ATSC, PSIP, FCC, ROI, AI, IP, KPI.
        return len(w) <= 4 and w.isupper() and any(c.isalpha() for c in w)

    def _is_shouting_word(w: str) -> bool:
        # Real shouting words are ≥ 5 chars (LIMITED, FREE, URGENT, OFFER).
        return len(w) >= 5 and w.isupper() and any(c.isalpha() for c in w)

    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if "!!" in line:
            multi_bang_lines.append(line[:80])
        words = line.split()
        alpha_words = [w for w in words if any(c.isalpha() for c in w)]
        # Drop acronyms from BOTH numerator and denominator so a line full
        # of acronyms doesn't count toward shouting at all.
        non_acronym_alpha = [w for w in alpha_words if not _is_acronym(w)]
        shouting_words = [w for w in non_acronym_alpha if _is_shouting_word(w)]
        if (
            len(non_acronym_alpha) >= 3
            and shouting_words
            and len(shouting_words) / len(non_acronym_alpha) >= 0.5
        ):
            shouting_lines.append(line[:80])
            continue
        # Detect inline run of 3+ consecutive ALL-CAPS NON-ACRONYM words.
        run = 0
        for w in words:
            if _is_shouting_word(w):
                run += 1
                if run >= 3:
                    shouting_lines.append(line[:80])
                    break
            else:
                run = 0

    if shouting_lines:
        findings.append(
            Finding(
                check="copygen.body_shouting",
                severity=Severity.MEDIUM,
                passed=False,
                message=(
                    f"The body uses capitals for whole words, starting with "
                    f'"{shouting_lines[0][:60]}". Write them in normal case.'
                ),
                details={"lines": shouting_lines[:5], "count": len(shouting_lines)},
            )
        )
    if multi_bang_lines:
        findings.append(
            Finding(
                check="copygen.body_shouting",
                severity=Severity.MEDIUM,
                passed=False,
                message=(
                    f"The body stacks exclamation marks, starting with "
                    f'"{multi_bang_lines[0][:60]}". Keep one at most.'
                ),
                details={"lines": multi_bang_lines[:5], "count": len(multi_bang_lines)},
            )
        )
    total_bangs = body.count("!")
    if total_bangs > 3:
        findings.append(
            Finding(
                check="copygen.body_shouting",
                severity=Severity.LOW,
                passed=False,
                message=(f"The body has {total_bangs} exclamation marks. Keep it to 3 or fewer."),
                details={"count": total_bangs},
            )
        )
    if not findings:
        findings.append(
            Finding(
                check="copygen.body_shouting",
                severity=Severity.INFO,
                passed=True,
                message=(
                    "The body does not use capitals for whole words or stack exclamation marks."
                ),
            )
        )
    return findings


def _check_body_newsletter_word(body: str) -> list[Finding]:
    if _NEWSLETTER_RX.search(body or ""):
        return [
            Finding(
                check="copygen.body_newsletter_word",
                severity=Severity.LOW,
                passed=False,
                message=(
                    "The body contains the word newsletter, which measures about 19 "
                    "percent worse on open rate. Say what is inside the email instead."
                ),
            )
        ]
    return [
        Finding(
            check="copygen.body_newsletter_word",
            severity=Severity.INFO,
            passed=True,
            message="The body does not use the word newsletter.",
        )
    ]


def _check_body_emoji(subject: str, body: str) -> list[Finding]:
    total = len(_EMOJI_RX.findall(subject or "")) + len(_EMOJI_RX.findall(body or ""))
    if total > 1:
        return [
            Finding(
                check="copygen.emoji_count",
                severity=Severity.MEDIUM,
                passed=False,
                message=(
                    f"The subject line and body together have {total} emoji. Keep one at most."
                ),
                details={"count": total},
            )
        ]
    return [
        Finding(
            check="copygen.emoji_count",
            severity=Severity.INFO,
            passed=True,
            message=f"The subject line and body together have {total} emoji.",
            details={"count": total},
        )
    ]
