"""Benefit-over-feature LLM check.

BENEFIT_FOCUSED → INFO PASS.
MIXED → LOW advisory.
FEATURE_ONLY → LOW advisory.
Skip paths: empty body, no API key, exception.
"""

from __future__ import annotations

import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.copywriting import benefit_over_feature  # noqa: E402
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
    monkeypatch, framing: str, reason: str, suggestions: list[str] | None = None,
):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    from audit.copywriting.benefit_over_feature import _Verdict
    v = _Verdict(framing=framing, reason=reason, suggestions=suggestions or [])
    fake = type("FakeOpenAI", (), {})()
    fake.AsyncOpenAI = lambda api_key=None: _Client(v)
    monkeypatch.setitem(sys.modules, "openai", fake)


def test_benefit_focused_passes(monkeypatch):
    _install(monkeypatch, "BENEFIT_FOCUSED", "Each feature framed as a reader outcome.")
    f = asyncio.run(benefit_over_feature.run(_email(
        "Hi Sarah, quartz counters mean you stop worrying about wine stains."
    )))[0]
    assert f.passed is True
    assert f.details["framing"] == "BENEFIT_FOCUSED"


def test_mixed_low(monkeypatch):
    _install(monkeypatch, "MIXED", "Some features framed; others bare.")
    f = asyncio.run(benefit_over_feature.run(_email(
        "Hi Sarah, quartz counters, 9-ft ceilings, smart thermostat. "
        "The thermostat learns your schedule so you don't think about it."
    )))[0]
    assert f.passed is False
    assert f.severity.value == "LOW"
    assert f.details["framing"] == "MIXED"


def test_feature_only_low(monkeypatch):
    _install(
        monkeypatch, "FEATURE_ONLY",
        "Bare list of specs, no reader context.",
        suggestions=[
            "Quartz counters mean you stop worrying about wine stains.",
            "9-ft ceilings make the main floor feel like double the square footage.",
            "Smart thermostat learns your schedule so you don't think about it.",
        ],
    )
    f = asyncio.run(benefit_over_feature.run(_email(
        "Hi Sarah, quartz counters, 9-ft ceilings, smart thermostat, "
        "stainless appliances, hardwood floors."
    )))[0]
    assert f.passed is False
    assert f.severity.value == "LOW"
    assert f.details["framing"] == "FEATURE_ONLY"
    assert len(f.details["suggestions"]) == 3


def test_skip_empty(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    f = asyncio.run(benefit_over_feature.run(_email("")))[0]
    assert f.passed is True
    assert f.details["skipped"] is True


def test_skip_no_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    f = asyncio.run(benefit_over_feature.run(_email("Hi, body content here.")))[0]
    assert f.passed is True
    assert f.details["skipped"] is True


def test_api_exception_skips(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    fake = type("FakeOpenAI", (), {})()
    def _raise(api_key=None):
        raise RuntimeError("boom")
    fake.AsyncOpenAI = _raise
    monkeypatch.setitem(sys.modules, "openai", fake)
    f = asyncio.run(benefit_over_feature.run(_email("Hi, body content here.")))[0]
    assert f.passed is True
    assert f.details["skipped"] is True
