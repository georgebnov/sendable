"""Curiosity-hook LLM check.

Skip paths: empty body, no API key, no openai, API exception.
Branches: OPEN_LOOP → INFO PASS; CLOSED_STATEMENT → LOW.
"""

from __future__ import annotations

import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.copywriting import curiosity_hook  # noqa: E402
from audit.parse import ParsedEmail  # noqa: E402


def _email(subject: str, plain: str) -> ParsedEmail:
    msg = EmailMessage()
    msg["From"] = "Emil <emil@b.com>"
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


def test_skip_empty_body(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    f = asyncio.run(curiosity_hook.run(_email("Subject", "")))[0]
    assert f.passed is True
    assert f.details["skipped"] is True


def test_skip_no_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    f = asyncio.run(curiosity_hook.run(_email("Subject", "Hi Sarah, opening here.")))[0]
    assert f.passed is True
    assert f.details["skipped"] is True


# ─── Mocked verdict branches ─────────────────────────────────────────


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
    monkeypatch, classification: str, reason: str, suggestions: list[str] | None = None,
):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    from audit.copywriting.curiosity_hook import _Verdict
    v = _Verdict(
        classification=classification, reason=reason, suggestions=suggestions or [],
    )
    fake = type("FakeOpenAI", (), {})()
    fake.AsyncOpenAI = lambda api_key=None: _Client(v)
    monkeypatch.setitem(sys.modules, "openai", fake)


def test_open_loop_passes(monkeypatch):
    _install(monkeypatch, "OPEN_LOOP", "Opens with an unresolved question.")
    f = asyncio.run(curiosity_hook.run(_email(
        "Three things I didn't expect at Lambton Mills",
        "Walked the floor this morning expecting one thing. Got something else entirely.",
    )))[0]
    assert f.passed is True
    assert f.details["classification"] == "OPEN_LOOP"


def test_closed_statement_low(monkeypatch):
    _install(
        monkeypatch, "CLOSED_STATEMENT",
        "Opens with a complete factual sentence.",
        suggestions=[
            "Three things surprised me about March — and one of them shifts pricing.",
            "Why did the slowest March in five years still close above ask?",
            "I expected one story this month. The data gave me a different one.",
        ],
    )
    f = asyncio.run(curiosity_hook.run(_email(
        "March market update",
        "Here is our March market update. We saw three sales this month.",
    )))[0]
    assert f.passed is False
    assert f.severity.value == "LOW"
    assert f.details["classification"] == "CLOSED_STATEMENT"
    assert len(f.details["suggestions"]) == 3


def test_api_exception_skips(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    fake = type("FakeOpenAI", (), {})()
    def _raise(api_key=None):
        raise RuntimeError("boom")
    fake.AsyncOpenAI = _raise
    monkeypatch.setitem(sys.modules, "openai", fake)
    f = asyncio.run(curiosity_hook.run(_email("S", "Body opening content.")))[0]
    assert f.passed is True
    assert f.details["skipped"] is True
