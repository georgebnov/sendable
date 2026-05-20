"""Social-proof / trust-signal LLM check.

has_trust_signal=True → INFO PASS.
has_trust_signal=False → LOW advisory.
Skip paths: empty body, no API key, exception.
"""

from __future__ import annotations

import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.copywriting import social_proof_presence  # noqa: E402
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
    monkeypatch, has_trust_signal: bool, reason: str, suggestions: list[str] | None = None,
):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    from audit.copywriting.social_proof_presence import _Verdict
    v = _Verdict(
        has_trust_signal=has_trust_signal, reason=reason,
        suggestions=suggestions or [],
    )
    fake = type("FakeOpenAI", (), {})()
    fake.AsyncOpenAI = lambda api_key=None: _Client(v)
    monkeypatch.setitem(sys.modules, "openai", fake)


def test_trust_signal_present_passes(monkeypatch):
    _install(monkeypatch, True, "Quotes 3.4% YoY appreciation and a TREB stat.")
    f = asyncio.run(social_proof_presence.run(_email(
        "Hi Sarah, units in Lambton Mills appreciated 3.4% YoY per TREB data."
    )))[0]
    assert f.passed is True


def test_no_trust_signal_low(monkeypatch):
    _install(
        monkeypatch, False,
        "Generic claims, no numbers or studies.",
        suggestions=[
            "Add a TREB stat: '[neighbourhood] appreciated [X%] over the last 12 months'.",
            "Cite a recent sale: '[address] just closed at [Y%] above ask in [N] days'.",
            "Drop a testimonial: '[client first name] referred two friends after their close.'",
        ],
    )
    f = asyncio.run(social_proof_presence.run(_email(
        "Hi Sarah, prices are strong right now. Lots of buyers. Tour Saturday?"
    )))[0]
    assert f.passed is False
    assert f.severity.value == "LOW"
    assert len(f.details["suggestions"]) == 3


def test_skip_empty(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    f = asyncio.run(social_proof_presence.run(_email("")))[0]
    assert f.passed is True
    assert f.details["skipped"] is True


def test_skip_no_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    f = asyncio.run(social_proof_presence.run(_email("Hi body here.")))[0]
    assert f.passed is True
    assert f.details["skipped"] is True


def test_api_exception_skips(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    fake = type("FakeOpenAI", (), {})()
    def _raise(api_key=None):
        raise RuntimeError("boom")
    fake.AsyncOpenAI = _raise
    monkeypatch.setitem(sys.modules, "openai", fake)
    f = asyncio.run(social_proof_presence.run(_email("Hi body here.")))[0]
    assert f.passed is True
    assert f.details["skipped"] is True
