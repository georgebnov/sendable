"""Smoke test: the adversarial fixture must trip the right critical checks."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from audit.parse import parse_eml  # noqa: E402
from audit.runner import audit  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "samples" / "adversarial.eml"


def test_adversarial_fixture_fails_as_expected() -> None:
    # domain_health=False keeps the suite hermetic — no DNS/SMTP/HTTPS calls.
    report = asyncio.run(audit(parse_eml(FIXTURE), domain_health=False))
    assert report.verdict == "NO_GO", (report.verdict, report.score)
    failing = {f.check for f in report.findings if not f.passed}
    assert "content.hidden_css_salting" in failing
    assert "content.homoglyphs" in failing
    assert "content.zero_width" in failing
