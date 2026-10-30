"""`just coverage` reads the right columns out of the pytest table.

The recipe answers one question: which file gets the next test. It did so by
taking the last field of each row as the percentage. With `show_missing` on,
the last field is a line number, so every row it printed was wrong, and the
list came out sorted by values that meant nothing. `engine/critic.py` showed as
`452%`, its last uncovered line.

The recipe now matches the percentage column instead of counting fields, and
this runs its real awk program, read out of the justfile, against a fixed row.
A guard that only catches a missing column would not catch the original bug:
the percentage was there, the recipe just read a different field.
"""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess

import pytest

JUSTFILE = pathlib.Path(__file__).parent.parent / "justfile"

# One row of `pytest --cov --cov-report=term` with branch coverage and
# show_missing on, which is what pyproject.toml configures:
#   Name  Stmts  Miss  Branch  BrPart  Cover  Missing
ROW = "engine/critic.py 171 22 100 21 83% 67, 76->78, 245->255, 452"


def _awk_program() -> str:
    """The awk program inside the `coverage` recipe, as the recipe runs it."""
    body = re.search(r"^coverage:\n(.*?)(?=\n\S)", JUSTFILE.read_text(), re.S | re.M)
    assert body, "the justfile has no coverage recipe"
    program = re.search(r"awk '(.*?)'", body.group(1), re.S)
    assert program, "the coverage recipe no longer runs awk"
    return program.group(1)


def _run(row: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["awk", _awk_program()],
        input=row + "\n",
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture(autouse=True)
def _needs_awk() -> None:
    if not shutil.which("awk"):
        pytest.skip("no awk on this machine")


def test_it_reads_the_percentage_and_not_a_line_number() -> None:
    """The bug in one assertion. 452 is the last uncovered line of the row."""
    out = _run(ROW).stdout
    assert out.startswith("83%"), (
        f"the recipe read {out.split(chr(9))[0]!r} as the coverage of "
        f"engine/critic.py. The row says 83%. Match the percentage column "
        f"rather than counting fields from either end."
    )
    assert "452" not in out.split("\t")[0]


def test_it_reads_the_missing_and_total_statements() -> None:
    """Which file to pick depends on the size of the gap, not only the
    percentage, so these two numbers have to come from the right columns."""
    assert _run(ROW).stdout.split("\t")[1] == "22 of 171 missing"


def test_the_file_name_survives() -> None:
    assert _run(ROW).stdout.rstrip("\n").split("\t")[2] == "engine/critic.py"


def test_a_table_without_a_percentage_column_fails_loudly() -> None:
    """Silence was the whole defect. A shape it cannot read must stop the run,
    not print a number it guessed."""
    done = _run("engine/critic.py 171 22 100 21 67, 76->78, 452")
    assert done.returncode != 0, "a row it cannot read must fail the recipe"
    assert "no percentage column" in done.stderr
    assert "Fix this recipe" in done.stderr
    assert done.stdout == "", "it printed a row it could not read"
