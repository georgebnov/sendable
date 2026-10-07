"""Shared fixtures.

Every test here runs with no network and no model call. The audit is called with
`domain_health=False`, which skips the DNS, blocklist, and SMTP checks, and the
`no_llm` fixture clears OPENAI_API_KEY so the model-backed checks take their
documented skip path and report INFO.

That combination makes the suite deterministic. A test that depends on a DNS
answer or on what a model said this time is a test that fails for reasons the
code did not cause.
"""

from __future__ import annotations

import pathlib

import pytest

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def no_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove the API key so no test can reach a model.

    Autouse on purpose. A single test that forgets this would make a paid call
    and return a different answer on the next run.
    """
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)


def load(name: str) -> bytes:
    """Read a .eml fixture by file name."""
    path = FIXTURES / name
    if not path.is_file():
        raise FileNotFoundError(f"no fixture named {name} in {FIXTURES}")
    return path.read_bytes()
