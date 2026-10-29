"""The report's wire format is a contract, so it is tested as one.

Both entry points print `to_jsonable(report)` as JSON on stdout, and an agent
reads that. The shape must not drift when the models change underneath, so this
file pins the field names, the field order, and the way an enum and a nested
model come out.
"""

from __future__ import annotations

import json

from engine.report import Finding, ModeInfo, Report, to_jsonable
from engine.severity import Severity


def _report() -> Report:
    return Report(
        score=7,
        verdict="NO_GO",
        findings=[
            Finding(
                check="a.b",
                severity=Severity.HIGH,
                passed=False,
                message="m",
                details={"k": 1},
            )
        ],
        subject="s",
    )


def test_the_wire_format_is_exactly_this() -> None:
    assert to_jsonable(_report()) == {
        "score": 7,
        "verdict": "NO_GO",
        "findings": [
            {
                "check": "a.b",
                "severity": "HIGH",
                "passed": False,
                "message": "m",
                "details": {"k": 1},
                "category": None,
                "family": None,
                "hard_gate": False,
                "source": "user_content",
            }
        ],
        "from_addr": None,
        "subject": "s",
        "sub_scores": {},
        "hard_gates_failed": [],
        "soft_multipliers_applied": [],
        "mode": {
            "label": "PRODUCTION",
            "signals": [],
            "cleanup_subject_prefix_stripped": None,
            "cleanup_headers_stripped": [],
            "cleanup_placeholders_substituted": [],
        },
    }


def test_the_severity_comes_out_as_its_name_not_an_object() -> None:
    """An agent reads `"HIGH"`. It must never see `"Severity.HIGH"`."""
    out = to_jsonable(_report())
    assert out["findings"][0]["severity"] == "HIGH"


def test_the_whole_thing_survives_json() -> None:
    """Nothing in a report needs a custom encoder."""
    text = json.dumps(to_jsonable(_report()))
    assert json.loads(text) == to_jsonable(_report())


def test_a_default_mode_block_is_always_present() -> None:
    """A report built without mode info still carries a valid mode block."""
    assert (
        to_jsonable(Report(score=1, verdict="NO_GO", findings=[]))["mode"]
        == (to_jsonable(Report(score=1, verdict="NO_GO", findings=[], mode=ModeInfo()))["mode"])
    )
