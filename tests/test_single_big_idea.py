"""Single-big-idea LLM check.

Verdict "1" → INFO PASS. "2" → MEDIUM. "3+" → HIGH.
Skip paths: empty body, no API key, no openai, API exception.
"""

from __future__ import annotations

import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.copywriting import single_big_idea  # noqa: E402
from audit.parse import ParsedEmail  # noqa: E402


def _email(plain: str) -> ParsedEmail:
    msg = EmailMessage()
    msg["From"] = "Emil <emil@b.com>"
    msg["Subject"] = "x"
    msg.set_content(plain, subtype="plain")
    headers: dict[str, list[str]] = {}
    for k, v in msg.items():
        headers.setdefault(k.lower(), []).append(str(v))
    return ParsedEmail(
        raw=msg,
        headers=headers,
        html=None,
        plain_text=plain,
        from_addr="Emil <emil@b.com>",
        to_addrs=[],
        subject="x",
        authentication_results=[],
    )


# ─── Mocked LLM scaffolding ──────────────────────────────────────────


class _Msg:
    def __init__(self, parsed): self.parsed = parsed
class _Choice:
    def __init__(self, parsed): self.message = _Msg(parsed)
class _Completion:
    def __init__(self, parsed): self.choices = [_Choice(parsed)]
class _ParseAPI:
    def __init__(self, v): self._v = v
    async def parse(self, **k): return _Completion(self._v)
class _Chat:
    def __init__(self, v): self.completions = _ParseAPI(v)
class _Beta:
    def __init__(self, v): self.chat = _Chat(v)
class _Client:
    def __init__(self, v): self.beta = _Beta(v)


def _install(
    monkeypatch, idea_count: str, reason: str, suggestions: list[str] | None = None,
):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    from audit.copywriting.single_big_idea import _Verdict
    v = _Verdict(
        idea_count=idea_count, reason=reason, suggestions=suggestions or [],
    )
    fake = type("FakeOpenAI", (), {})()
    fake.AsyncOpenAI = lambda api_key=None: _Client(v)
    monkeypatch.setitem(sys.modules, "openai", fake)


# ─── Branches ────────────────────────────────────────────────────────


def test_single_idea_passes(monkeypatch):
    _install(monkeypatch, "1", "Body is a single pitch on Lambton Mills.")
    f = asyncio.run(single_big_idea.run(_email(
        "Hi Sarah, Lambton Mills launches Saturday. Pricing matches your budget. Tour?"
    )))[0]
    assert f.passed is True
    assert f.details["idea_count"] == "1"


def test_two_ideas_medium(monkeypatch):
    _install(monkeypatch, "2", "Body pitches both a tour and a separate valuation.")
    f = asyncio.run(single_big_idea.run(_email(
        "Hi Sarah, Lambton Mills launches Saturday. Also our free home "
        "valuation tool is now live."
    )))[0]
    assert f.passed is False
    assert f.severity.value == "MEDIUM"


def test_three_or_more_ideas_high(monkeypatch):
    _install(
        monkeypatch, "3+",
        "Body covers tour, valuation, and referral.",
        suggestions=[
            "Keep: Saturday tour. Cut: valuation, referral. Angle: build curiosity around the unit.",
            "Keep: valuation tool launch. Cut: tour, referral. Angle: demo the tool with one example.",
            "Keep: referral. Cut: tour, valuation. Angle: name the reward and one past success.",
        ],
    )
    f = asyncio.run(single_big_idea.run(_email(
        "Tour Saturday. Home valuation tool live. Refer a friend."
    )))[0]
    assert f.passed is False
    assert f.severity.value == "HIGH"
    assert len(f.details["suggestions"]) == 3


# ─── Skip paths ──────────────────────────────────────────────────────


def test_skip_empty_body(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    f = asyncio.run(single_big_idea.run(_email("")))[0]
    assert f.passed is True
    assert f.details["skipped"] is True


def test_skip_no_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    f = asyncio.run(single_big_idea.run(_email("Hi, content here.")))[0]
    assert f.passed is True
    assert f.details["skipped"] is True


def test_api_exception_skips(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    fake = type("FakeOpenAI", (), {})()
    def _raise(api_key=None):
        raise RuntimeError("boom")
    fake.AsyncOpenAI = _raise
    monkeypatch.setitem(sys.modules, "openai", fake)
    f = asyncio.run(single_big_idea.run(_email("Hi, content here.")))[0]
    assert f.passed is True
    assert f.details["skipped"] is True
