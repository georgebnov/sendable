"""Majority-vote wrapper for the wobbly LLM audit judges.

`call_structured_majority` runs the underlying judge N times and returns the
sample whose keyed label wins a majority vote. This is the self-consistency
fix that stops `single_big_idea` / `benefit_over_feature` from flip-flopping on
borderline drafts (a single LLM judge call has low intra-rater agreement). The
real LLM is never called here — we monkeypatch the inner `call_structured` to
feed a controlled sequence of verdicts so the aggregation is deterministic.
"""

from __future__ import annotations

import pytest
from pydantic import BaseModel

import engine.llm as llm


class _V(BaseModel):
    label: str
    reason: str = ""


def _feed(monkeypatch, sequence):
    """Make the next N call_structured calls return `sequence` in order
    (None entries simulate a failed/skipped sample)."""
    queue = list(sequence)

    async def fake(**_kwargs):
        return queue.pop(0)

    monkeypatch.setattr(llm, "call_structured", fake)


async def _vote(n=3):
    return await llm.call_structured_majority(
        check="t",
        model="m",
        system="s",
        user="u",
        response_format=_V,
        key=lambda v: v.label,
        n=n,
    )


async def test_majority_picks_the_modal_label(monkeypatch):
    _feed(monkeypatch, [_V(label="A"), _V(label="A"), _V(label="B")])
    out = await _vote()
    assert out is not None and out.label == "A"


async def test_majority_is_order_independent(monkeypatch):
    _feed(monkeypatch, [_V(label="B"), _V(label="A"), _V(label="A")])
    out = await _vote()
    assert out is not None and out.label == "A"


async def test_majority_keeps_the_winning_samples_payload(monkeypatch):
    # The returned object is a real winning sample, so its reason survives.
    _feed(
        monkeypatch,
        [
            _V(label="MIXED", reason="one bare spec"),
            _V(label="MIXED", reason="two bare specs"),
            _V(label="BENEFIT_FOCUSED", reason="all framed"),
        ],
    )
    out = await _vote()
    assert out is not None and out.label == "MIXED"
    assert "bare spec" in out.reason


async def test_majority_filters_failed_samples(monkeypatch):
    _feed(monkeypatch, [None, _V(label="A"), None])
    out = await _vote()
    assert out is not None and out.label == "A"


async def test_majority_none_when_every_sample_fails(monkeypatch):
    _feed(monkeypatch, [None, None, None])
    assert await _vote() is None


async def test_tie_breaks_to_first_seen(monkeypatch):
    # Even N, perfect split -> earliest-sampled label wins (stable, not random).
    _feed(monkeypatch, [_V(label="A"), _V(label="B")])
    out = await _vote(n=2)
    assert out is not None and out.label == "A"


@pytest.mark.parametrize("rotation", [0, 1, 2])
async def test_verdict_is_stable_across_runs(monkeypatch, rotation):
    """The whole point: a borderline draft that the judge calls 2-of-3 one way
    yields the SAME verdict no matter how the samples are ordered — no
    flip-flop between audit runs."""
    base = [_V(label="A"), _V(label="A"), _V(label="B")]
    seq = base[rotation:] + base[:rotation]
    _feed(monkeypatch, seq)
    out = await _vote()
    assert out is not None and out.label == "A"
