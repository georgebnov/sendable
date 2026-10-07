"""Shared async LLM caller for audit checks.

Why this module exists:
  - Every LLM-backed check has the same boilerplate (env-var check,
    openai import, client init, structured-output parse, exception
    swallowing). Five copies of that drift over time.
  - Without truly-async I/O, `asyncio.gather` over the check list runs
    LLM calls sequentially — each blocks the event loop. Real
    concurrency needs `AsyncOpenAI` with `await`.
  - Token usage + cost telemetry should be centralised so adding a new
    LLM check doesn't require reimplementing accounting.

Pricing (USD per 1M tokens) — gpt-4o-mini, current OpenAI rate card:
  input:  $0.150
  output: $0.600

Per-call cost is logged to stderr immediately after each call. A
ContextVar accumulator lets the audit runner sum and emit a total per
audit run.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import os
import sys
import time
from collections import Counter
from collections.abc import Callable, Hashable
from typing import TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)

# gpt-4o-mini pricing (per OpenAI rate card, USD per token).
_PRICE_PER_INPUT_TOKEN = 0.150 / 1_000_000
_PRICE_PER_OUTPUT_TOKEN = 0.600 / 1_000_000

# Per-audit cost accumulator. The runner resets this at audit start and
# reads it at the end to emit a total. Per-call logging still happens
# regardless.
_cost_accumulator: contextvars.ContextVar[dict | None] = contextvars.ContextVar(
    "audit_llm_cost",
    default=None,
)


def reset_accumulator() -> None:
    """Initialise a fresh per-audit accumulator. Call at audit start."""
    _cost_accumulator.set({"calls": 0, "in": 0, "out": 0, "usd": 0.0})


def get_accumulator() -> dict | None:
    return _cost_accumulator.get()


async def _safe_close(client) -> None:
    """Best-effort close of an AsyncOpenAI client. Swallows any error
    so a cleanup hiccup never masks the actual result."""
    with contextlib.suppress(Exception):
        await client.close()


def _add(in_tok: int, out_tok: int, usd: float) -> None:
    acc = _cost_accumulator.get()
    if acc is None:
        return
    acc["calls"] += 1
    acc["in"] += in_tok
    acc["out"] += out_tok
    acc["usd"] += usd


async def call_structured(
    *,
    check: str,
    model: str,
    system: str,
    user: str,
    response_format: type[T],
) -> T | None:
    """Make one structured-output call (async).

    Returns parsed model instance, or None on any failure (missing API
    key, package not importable, network error, schema mismatch).
    Callers must handle the None case with a defensive INFO-PASS skip.

    Logs `[llm] <check> in=N out=M cost=$X.XXXXXX  T.TTs` to stderr
    after each call. Also increments the per-audit ContextVar
    accumulator so the runner can emit a total at end-of-audit.
    """
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        return None
    try:
        from openai import AsyncOpenAI
    except ImportError:
        return None

    # AsyncOpenAI owns an httpx.AsyncClient with a TCP connection pool.
    # We close it explicitly after each call so the pool's __del__ doesn't
    # fire after the event loop teardown (which produces noisy
    # "RuntimeError: unable to perform operation on <TCPTransport closed>"
    # warnings in stderr when many calls run concurrently inside a
    # short-lived asyncio.run).
    t0 = time.monotonic()
    client = None
    try:
        # 30s cap per LLM call so the audit's total wall time stays well below
        # SQS visibility timeout even if a tail call hangs.
        client = AsyncOpenAI(api_key=api_key, timeout=30.0)
        completion = await client.beta.chat.completions.parse(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            response_format=response_format,
        )
    except Exception as e:
        elapsed = time.monotonic() - t0
        print(
            f"[llm] {check} FAIL ({type(e).__name__}: {e}) {elapsed:.2f}s",
            file=sys.stderr,
        )
        if client is not None:
            await _safe_close(client)
        return None
    await _safe_close(client)

    elapsed = time.monotonic() - t0
    usage = getattr(completion, "usage", None)
    in_tok = getattr(usage, "prompt_tokens", 0) if usage else 0
    out_tok = getattr(usage, "completion_tokens", 0) if usage else 0
    cost = in_tok * _PRICE_PER_INPUT_TOKEN + out_tok * _PRICE_PER_OUTPUT_TOKEN
    _add(in_tok, out_tok, cost)
    print(
        f"[llm] {check} in={in_tok} out={out_tok} cost=${cost:.6f} {elapsed:.2f}s",
        file=sys.stderr,
    )
    return completion.choices[0].message.parsed


async def call_structured_majority(
    *,
    check: str,
    model: str,
    system: str,
    user: str,
    response_format: type[T],
    key: Callable[[T], Hashable],
    n: int = 3,
) -> T | None:
    """Run `call_structured` N times and return the sample whose `key(...)`
    label wins a majority vote — the self-consistency fix for wobbly LLM
    judges (single LLM judge calls have low intra-rater agreement, so one
    call is near a coin-flip on borderline inputs; the mode of N stabilises
    the emitted verdict so a near-identical redraft lands the same finding).

    Sampling diversity is REQUIRED for this to work, so we deliberately do
    NOT pin temperature to 0 — identical samples would make the vote
    meaningless. We keep the returned object (not just its label) so the
    caller still gets a representative `reason` / `suggestions`.

    Returns None only if every sample failed (caller keeps its INFO-PASS
    skip). Ties are broken by first appearance (Counter preserves insertion
    order), so the earliest-sampled label wins.
    """
    samples = await asyncio.gather(
        *(
            call_structured(
                check=check,
                model=model,
                system=system,
                user=user,
                response_format=response_format,
            )
            for _ in range(max(1, n))
        )
    )
    results = [s for s in samples if s is not None]
    if not results:
        return None
    winning_label = Counter(key(r) for r in results).most_common(1)[0][0]
    for r in results:
        if key(r) == winning_label:
            return r
    return results[0]  # unreachable — winning_label always matches some sample
