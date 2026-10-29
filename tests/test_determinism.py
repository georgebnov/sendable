"""The same message always produces the same bytes.

Rule 7: nothing is written to disk and nothing carries between runs, so a
second audit of the same input must return the first answer exactly. That only
holds if every ordered thing in the audit is ordered by something stable.

A set of strings is not. Python randomises string hashing per process, so
iterating a set gives a different order in each new interpreter. These tests
run the real entry point in separate processes with different PYTHONHASHSEED
values, which is the only way to see that from inside a test suite.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "broken_bulk.eml"


def _audit_with_seed(seed: str) -> str:
    env = {**os.environ, "PYTHONHASHSEED": seed}
    out = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "audit.py"), str(FIXTURE), "--offline"],
        capture_output=True,
        text=True,
        env=env,
        cwd=ROOT,
        check=True,
    )
    return out.stdout


def test_two_runs_produce_identical_bytes() -> None:
    assert _audit_with_seed("0") == _audit_with_seed("12345")


def test_the_subscore_order_is_the_declared_order() -> None:
    """Ordered by the weights table, not by whatever a set hands back."""
    from engine.scoring import CATEGORY_WEIGHTS

    report = json.loads(_audit_with_seed("99"))
    assert list(report["sub_scores"]) == list(CATEGORY_WEIGHTS)
