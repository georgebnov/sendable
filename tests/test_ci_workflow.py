"""A CI workflow cancels an old run only on a pull request, never on ``main``.

A ``concurrency`` block puts runs into a named group. GitHub then does two things to the group:

1. With ``cancel-in-progress: true``, a new run cancels the run that is already running.
2. Always, even with ``cancel-in-progress: false``, the group holds at most one *pending* run,
   and a newer pending run cancels the older pending one.

On a pull request both are what we want: a new push makes the old run useless. On ``main`` they
are a defect. Every push to ``main`` is a merged commit, and if a later merge cancels its run,
that commit never gets a result. So two rules, checked on every workflow file and on every
block, workflow-level and job-level alike:

- ``cancel-in-progress`` is true only for a pull request.
- The group of every other run holds ``github.run_id`` inside an expression, so each ``main``
  run has a group of its own and nothing can cancel it, pending or running.

The repo declares no YAML parser and rule 13 keeps it that way, so this reads the one plain
form below and fails on every other spelling. A line that mentions ``concurrency`` and is not
that form (a quoted key, a flow mapping, a ``run:`` script that prints the word) fails too: a
block this scan cannot read is a block nobody checked. A ``group`` or ``cancel-in-progress``
line with a trailing comment fails for the same reason. The one spelling it cannot see is a key
written with a YAML escape such as ``"concur\\u0072ency"``.

A workflow that truly must run one at a time (a release, say) would need one fixed group with
``cancel-in-progress: false``. None exists yet; adding one means adding it here with its reason.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"
PR_ONLY_CANCEL = "${{ github.event_name == 'pull_request' }}"
OWN_GROUP = "${{ github.event_name == 'pull_request' && github.ref || github.run_id }}"
GOOD = f"""\
concurrency:
  group: ${{{{ github.workflow }}}}-{OWN_GROUP}
  cancel-in-progress: {PR_ONLY_CANCEL}
"""
FIX = f"Fix: write the block in exactly this form.\n{GOOD}"

_KEY = re.compile(r"^( *)concurrency:\s*(#.*)?$")
_FIELD = re.compile(r"^ +(group|cancel-in-progress):\s+(\S.*?)\s*$")
# YAML starts a comment at a "#" that follows white space. The text after it is not part of the
# value, so a value that holds one is not read: the comment could hold the form and hide the value.
_COMMENT = re.compile(r"\s#")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _is_blank_or_comment(line: str) -> bool:
    return not line.strip() or line.lstrip().startswith("#")


def _violations(name: str, text: str) -> list[str]:
    """Every broken rule in one workflow file, each as ``file:line: what is wrong``."""
    lines = text.splitlines()
    found: list[str] = []
    for number, line in enumerate(lines, start=1):
        if _is_blank_or_comment(line) or "concurrency" not in line:
            continue
        where = f"{name}:{number}"
        key = _KEY.match(line)
        if key is None:
            found.append(f"{where}: cannot read this spelling: {line.strip()}")
            continue
        fields: dict[str, str] = {}
        for child in lines[number:]:
            if _is_blank_or_comment(child):
                continue
            if _indent(child) <= len(key.group(1)):
                break
            field = _FIELD.match(child)
            if field is None or field.group(1) in fields or _COMMENT.search(field.group(2)):
                found.append(f"{where}: cannot read this line of the block: {child.strip()}")
                continue
            fields[field.group(1)] = field.group(2).strip("\"'")
        cancel = fields.get("cancel-in-progress", "false")
        if cancel not in ("false", PR_ONLY_CANCEL):
            found.append(
                f"{where}: cancel-in-progress: {cancel} can cancel a run on main. "
                "Only a pull request run may be cancelled."
            )
        group = fields.get("group", "")
        if OWN_GROUP not in group:
            found.append(
                f"{where}: group: {group} is shared by the runs on main, so a later merge "
                "cancels the pending run of an earlier one."
            )
    return found


def test_no_workflow_can_cancel_a_run_on_main() -> None:
    paths = sorted(WORKFLOWS.glob("*.y*ml"))
    assert paths, f"no workflow file found in {WORKFLOWS}"
    bad = [
        violation
        for path in paths
        for violation in _violations(path.name, path.read_text(encoding="utf-8"))
    ]
    assert not bad, "\n".join([*bad, FIX])


def test_the_fix_it_names_passes() -> None:
    assert _violations("ok.yml", GOOD) == []


# Each of these lets a later run cancel a run on main, or hides a block from the scan. The
# second value is the line the report must name.
BAD = {
    "the block this repo shipped": (
        "concurrency:\n  group: skill-${{ github.ref }}\n  cancel-in-progress: true\n",
        "x.yml:1: cancel-in-progress: true",
    ),
    "a job-level block": (
        "jobs:\n  gate:\n    concurrency:\n      group: gate-${{ github.ref }}\n"
        "      cancel-in-progress: true\n",
        "x.yml:3: cancel-in-progress: true",
    ),
    "a fixed group that never cancels a running run": (
        "concurrency:\n  group: deploy\n  cancel-in-progress: false\n",
        "x.yml:1: group: deploy",
    ),
    "the expression as plain text, which GitHub does not evaluate": (
        "concurrency:\n"
        "  group: \"skill-github.event_name == 'pull_request' && github.ref || github.run_id\"\n",
        "x.yml:1: group: skill-github.event_name",
    ),
    "a bare group name": (
        "concurrency: skill-${{ github.ref }}\n",
        "x.yml:1: cannot read this spelling",
    ),
    "a quoted key": (
        f'"concurrency":\n  group: {OWN_GROUP}\n',
        "x.yml:1: cannot read this spelling",
    ),
    "a flow mapping": (
        "jobs: {gate: {concurrency: {group: shared, cancel-in-progress: true}}}\n",
        "x.yml:1: cannot read this spelling",
    ),
    "a shared group with the expression in a trailing comment": (
        f"concurrency:\n  group: shared # {OWN_GROUP}\n  cancel-in-progress: false\n",
        "x.yml:1: cannot read this line of the block: group: shared #",
    ),
    "a second key that overrides the first": (
        f"concurrency:\n  group: {OWN_GROUP}\n  cancel-in-progress: false\n"
        "  cancel-in-progress: true\n",
        "x.yml:1: cannot read this line of the block: cancel-in-progress: true",
    ),
}


@pytest.mark.parametrize("case", BAD)
def test_the_scan_reports(case: str) -> None:
    text, expected = BAD[case]
    assert any(expected in violation for violation in _violations("x.yml", text)), _violations(
        "x.yml", text
    )
