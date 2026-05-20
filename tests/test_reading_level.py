"""Reading-level (Flesch-Kincaid) check tests.

Bands enforced:
  - Grade ≤9 → INFO PASS
  - Grade 10-12 → MEDIUM
  - Grade ≥13 → HIGH
  - Sample too small → INFO PASS (no grade reported)
"""

from __future__ import annotations

import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.copywriting.reading_level import (  # noqa: E402
    _count_syllables,
    _flesch_kincaid_grade,
    run,
)
from audit.parse import ParsedEmail  # noqa: E402


def _email(plain: str) -> ParsedEmail:
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["Subject"] = "Test"
    msg.set_content(plain, subtype="plain")
    headers: dict[str, list[str]] = {}
    for k, v in msg.items():
        headers.setdefault(k.lower(), []).append(str(v))
    return ParsedEmail(
        raw=msg,
        headers=headers,
        html=None,
        plain_text=plain,
        from_addr="sender@example.com",
        to_addrs=[],
        subject="Test",
        authentication_results=[],
    )


# ─── Syllable counter unit tests ──────────────────────────────────────


def test_syllable_basic():
    assert _count_syllables("hello") == 2
    assert _count_syllables("cat") == 1
    assert _count_syllables("table") == 2          # -le retained
    assert _count_syllables("candles") == 2        # -les retained
    assert _count_syllables("make") == 1           # silent trailing e


def test_syllable_multisyllable():
    assert _count_syllables("beautiful") == 3      # beau-ti-ful (vowel-cluster)
    assert _count_syllables("notwithstanding") == 4


def test_syllable_minimum_one():
    assert _count_syllables("rhythm") == 1


# ─── FK grade unit tests ──────────────────────────────────────────────


def test_grade_too_small_sample():
    grade, stats = _flesch_kincaid_grade("Short. Text. Here.")
    assert grade is None
    assert stats["words"] < 30


def test_grade_conversational_text():
    text = (
        "Hi there. Want to grab coffee next week? "
        "I have a few new homes to show you. They are nice. "
        "Let me know what day works for you. "
        "We can meet at the cafe on Main Street. "
        "I will bring the listings and a map. "
        "It should be a quick chat, an hour at most. "
        "Talk soon."
    )
    grade, _ = _flesch_kincaid_grade(text)
    assert grade is not None
    assert grade <= 9, grade


def test_grade_academic_text():
    text = (
        "The aforementioned investigation demonstrates conclusively that "
        "contemporary metropolitan housing developments necessitate "
        "comprehensive interdisciplinary methodological frameworks. "
        "Subsequent quantitative assessments corroborate the preliminary "
        "hypothesis regarding multifaceted demographic transformations. "
        "Furthermore, longitudinal observational documentation substantiates "
        "predominant theoretical interpretations articulated previously."
    )
    grade, _ = _flesch_kincaid_grade(text)
    assert grade is not None
    assert grade >= 13, grade


# ─── Finding-level integration ────────────────────────────────────────


def test_run_emits_info_when_too_short():
    findings = asyncio.run(run(_email("Hi. Quick note. Bye.")))
    assert len(findings) == 1
    f = findings[0]
    assert f.check == "copywriting.reading_level"
    assert f.passed is True
    assert f.severity.value == "INFO"


def test_run_pass_on_conversational():
    plain = (
        "Hi there. Want to grab coffee next week? "
        "I have a few new homes to show you. They are nice. "
        "Let me know what day works for you. "
        "We can meet at the cafe on Main Street. "
        "I will bring the listings and a map. "
        "It should be a quick chat. "
        "Talk soon."
    )
    findings = asyncio.run(run(_email(plain)))
    assert len(findings) == 1
    f = findings[0]
    assert f.passed is True
    assert f.severity.value == "INFO"
    assert f.details["grade"] <= 9


def test_run_high_on_academic():
    plain = (
        "The aforementioned investigation demonstrates conclusively that "
        "contemporary metropolitan housing developments necessitate "
        "comprehensive interdisciplinary methodological frameworks. "
        "Subsequent quantitative assessments corroborate the preliminary "
        "hypothesis regarding multifaceted demographic transformations. "
        "Furthermore, longitudinal observational documentation substantiates "
        "predominant theoretical interpretations articulated previously."
    )
    findings = asyncio.run(run(_email(plain)))
    assert len(findings) == 1
    f = findings[0]
    assert f.passed is False
    assert f.severity.value == "HIGH"
    assert f.details["grade"] >= 13
