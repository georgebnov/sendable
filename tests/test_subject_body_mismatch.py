"""Subject vs body semantic-alignment check.

Tests cover the defensive skip paths (no API key, no subject/body) and
the two success branches via a monkeypatched OpenAI client. Real LLM
calls are never made.
"""

from __future__ import annotations

import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.copywriting import subject_body_mismatch  # noqa: E402
from audit.parse import ParsedEmail  # noqa: E402


def _email(subject: str | None, plain: str) -> ParsedEmail:
    msg = EmailMessage()
    msg["From"] = "Emil <emil@b.com>"
    if subject is not None:
        msg["Subject"] = subject
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
        subject=subject,
        authentication_results=[],
    )


# ─── Skip paths ──────────────────────────────────────────────────────


def test_skip_when_no_subject(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    f = asyncio.run(subject_body_mismatch.run(_email(None, "Body content here.")))[0]
    assert f.passed is True
    assert f.details["skipped"] is True


def test_skip_when_no_body(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    f = asyncio.run(subject_body_mismatch.run(_email("Subject", "")))[0]
    assert f.passed is True
    assert f.details["skipped"] is True


def test_skip_when_no_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    f = asyncio.run(subject_body_mismatch.run(
        _email("New listings", "Hi Sarah, listings inside.")
    ))[0]
    assert f.passed is True
    assert f.details["skipped"] is True


# ─── Mocked LLM branches ─────────────────────────────────────────────


class _FakeMsg:
    def __init__(self, parsed): self.parsed = parsed


class _FakeChoice:
    def __init__(self, parsed): self.message = _FakeMsg(parsed)


class _FakeCompletion:
    def __init__(self, parsed): self.choices = [_FakeChoice(parsed)]


class _FakeParseAPI:
    def __init__(self, verdict): self._verdict = verdict
    async def parse(self, **kwargs): return _FakeCompletion(self._verdict)


class _FakeChat:
    def __init__(self, verdict):
        self.completions = _FakeParseAPI(verdict)


class _FakeBeta:
    def __init__(self, verdict):
        self.chat = _FakeChat(verdict)


class _FakeClient:
    def __init__(self, verdict):
        self.beta = _FakeBeta(verdict)


def _install_fake_openai(
    monkeypatch, matches: bool, reason: str, suggestions: list[str] | None = None,
):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    from audit.copywriting.subject_body_mismatch import _Verdict
    verdict = _Verdict(
        matches=matches, reason=reason, suggestions=suggestions or [],
    )
    fake = type("FakeOpenAIModule", (), {})()
    fake.AsyncOpenAI = lambda api_key=None: _FakeClient(verdict)
    monkeypatch.setitem(sys.modules, "openai", fake)


def test_aligned_subject_passes(monkeypatch):
    _install_fake_openai(monkeypatch, matches=True, reason="Both discuss the Lambton Mills launch.")
    f = asyncio.run(subject_body_mismatch.run(_email(
        "Lambton Mills launches Saturday",
        "Hi Sarah, Lambton Mills opens Saturday at 11am. Pricing inside.",
    )))[0]
    assert f.passed is True
    assert f.severity.value == "INFO"
    assert "Lambton Mills" in f.details["reason"]


def test_mismatched_subject_high(monkeypatch):
    _install_fake_openai(
        monkeypatch,
        matches=False,
        reason="Subject promises a free home valuation but body discusses an unrelated tour.",
        suggestions=[
            "Tour confirmation: Lambton Mills Saturday",
            "Quick confirm — Saturday tour at Lambton Mills",
            "Saturday tour locked at Lambton Mills",
        ],
    )
    f = asyncio.run(subject_body_mismatch.run(_email(
        "Your free home valuation is ready",
        "Hi Sarah, just confirming Saturday tour at Lambton Mills.",
    )))[0]
    assert f.passed is False
    assert f.severity.value == "HIGH"
    assert "CAN-SPAM" in f.message
    assert len(f.details["suggestions"]) == 3
    assert all(isinstance(s, str) and s for s in f.details["suggestions"])


def test_api_exception_skips_gracefully(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    fake = type("FakeOpenAIModule", (), {})()
    def _raise(api_key=None):
        raise RuntimeError("boom")
    fake.AsyncOpenAI = _raise
    monkeypatch.setitem(sys.modules, "openai", fake)
    f = asyncio.run(subject_body_mismatch.run(_email(
        "Subject", "Body text here for the test.",
    )))[0]
    assert f.passed is True
    assert f.details["skipped"] is True
