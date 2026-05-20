"""Local-specificity check.

Regex pass first; LLM fallback only when no regex anchor.
PASS via regex → no LLM call.
LLM fallback handles slang/non-pattern names.
"""

from __future__ import annotations

import asyncio
import sys
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.industry.real_estate import local_specificity  # noqa: E402
from audit.industry.real_estate.local_specificity import _regex_scan  # noqa: E402
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


# ─── Regex unit tests ────────────────────────────────────────────────


def test_regex_prep_location():
    hits = _regex_scan("Pricing came in at Lambton Mills today.")
    assert any(h.startswith("prep:Lambton Mills") for h in hits)


def test_regex_anchor_suffix():
    hits = _regex_scan("The Bayview corridor saw three new listings.")
    assert any("corridor" in h for h in hits)


def test_regex_intersection():
    hits = _regex_scan("Tour at Yonge and Eglinton this Saturday.")
    assert any(h.startswith("intersection:") for h in hits)


def test_regex_street_address():
    hits = _regex_scan("Showing at 142 Lambton Avenue Saturday morning.")
    assert any(h.startswith("address:") for h in hits)


def test_regex_postal_code_canadian():
    hits = _regex_scan("Postal M6S 1A1 — let me know.")
    assert any(h.startswith("postal:") for h in hits)


def test_regex_negative_after_prep_skipped():
    """'in May' / 'at any time' must not register as a location."""
    hits = _regex_scan("We can meet in May at any time you prefer.")
    assert not any(h.startswith("prep:") for h in hits)


# ─── Integration: regex PASS path (no LLM call) ──────────────────────


def test_regex_pass_no_llm_called(monkeypatch):
    """When regex finds an anchor, OPENAI_API_KEY presence is irrelevant
    and the OpenAI module must not be imported."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    body = "Hi Sarah, pricing locked at Lambton Mills this morning.\n\nBest,\nEmil"
    f = asyncio.run(local_specificity.run(_email(body)))[0]
    assert f.passed is True
    assert f.details.get("regex_pass") is True


# ─── LLM fallback paths ──────────────────────────────────────────────


class _FakeMsg:
    def __init__(self, parsed): self.parsed = parsed
class _FakeChoice:
    def __init__(self, parsed): self.message = _FakeMsg(parsed)
class _FakeCompletion:
    def __init__(self, parsed): self.choices = [_FakeChoice(parsed)]
class _FakeParse:
    def __init__(self, verdict): self._v = verdict
    async def parse(self, **k): return _FakeCompletion(self._v)
class _FakeChat:
    def __init__(self, v): self.completions = _FakeParse(v)
class _FakeBeta:
    def __init__(self, v): self.chat = _FakeChat(v)
class _FakeClient:
    def __init__(self, v): self.beta = _FakeBeta(v)


def _install_fake_openai(
    monkeypatch, has_location: bool, reason: str, suggestions: list[str] | None = None,
):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    from audit.industry.real_estate.local_specificity import _Verdict
    v = _Verdict(
        has_location=has_location, reason=reason, suggestions=suggestions or [],
    )
    fake = type("FakeOpenAIModule", (), {})()
    fake.AsyncOpenAI = lambda api_key=None: _FakeClient(v)
    monkeypatch.setitem(sys.modules, "openai", fake)


def test_llm_fallback_pass(monkeypatch):
    _install_fake_openai(monkeypatch, has_location=True, reason="Mentions 'the Junction'.")
    body = (
        "Hi Sarah, the Junction has been heating up over the last quarter. "
        "Three off-MLS pockets dropped this week. Worth a call?\n\nBest,\nEmil"
    )
    f = asyncio.run(local_specificity.run(_email(body)))[0]
    assert f.passed is True
    assert f.details["via"] == "llm"


def test_llm_fallback_medium(monkeypatch):
    _install_fake_openai(
        monkeypatch,
        has_location=False,
        reason="No named location.",
        suggestions=[
            "The [Junction] market has been strong this quarter.",
            "Three sales above ask in [Roncesvalles] this month.",
            "Listings near [Bloor and Lansdowne] continue to clear quickly.",
        ],
    )
    body = (
        "Hi Sarah, your local market has been strong this quarter. Several "
        "homes in the area sold above ask. Let's chat soon.\n\nBest,\nEmil"
    )
    f = asyncio.run(local_specificity.run(_email(body)))[0]
    assert f.passed is False
    assert f.severity.value == "MEDIUM"
    assert f.details["via"] == "llm"
    assert len(f.details["suggestions"]) == 3


def test_skip_when_no_api_key_and_no_regex(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    body = "Hi Sarah, your local market is strong. Talk soon.\n\nBest,\nEmil"
    f = asyncio.run(local_specificity.run(_email(body)))[0]
    assert f.passed is True
    assert f.details["skipped"] is True
