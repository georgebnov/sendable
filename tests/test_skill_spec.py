"""SKILL.md against the Agent Skills specification.

The spec lives at https://agentskills.io/specification.md and is the open format
many agents read, not a Claude-only one. It ships a validator, `skills-ref
validate`, which needs `npx`. This repo cannot run that: the environment blocks
external package execution and the global rules forbid it.

So the rules live here instead, which is better anyway. `just check` and CI run
them on every commit, where a validator someone has to remember to install runs
never.

Only the spec's own constraints are asserted. Style belongs in review.
"""

from __future__ import annotations

import pathlib
import re

import pytest

SKILL = pathlib.Path("SKILL.md")
# The spec's own field list. Anything else in the frontmatter is a typo or a
# field invented locally, and both are worth failing on.
ALLOWED = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}


def _frontmatter() -> dict[str, str]:
    text = SKILL.read_text()
    assert text.startswith("---\n"), "SKILL.md must open with YAML frontmatter"
    body = text.split("---\n", 2)
    assert len(body) >= 3, "frontmatter is not closed"
    out: dict[str, str] = {}
    for line in body[1].splitlines():
        if not line.strip() or line.startswith((" ", "\t", "#")):
            continue
        key, _, value = line.partition(":")
        out[key.strip()] = value.strip().strip('"')
    return out


@pytest.fixture(scope="module")
def fm() -> dict[str, str]:
    return _frontmatter()


# ── required fields ───────────────────────────────────────────────────


def test_name_and_description_are_present(fm: dict[str, str]) -> None:
    assert fm.get("name"), "name is required"
    assert fm.get("description"), "description is required and must be non-empty"


def test_the_name_matches_its_own_rules(fm: dict[str, str]) -> None:
    name = fm["name"]
    assert 1 <= len(name) <= 64, f"name is {len(name)} characters, the limit is 64"
    assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", name), (
        f"{name!r}: lowercase letters, numbers and single hyphens only, "
        "and it may not start or end with a hyphen"
    )


def test_the_name_matches_the_directory_it_installs_as(fm: dict[str, str]) -> None:
    # The spec requires the folder name to equal the frontmatter name. Install
    # this repo under any other folder name and a strict client rejects it.
    assert fm["name"] == pathlib.Path.cwd().name, (
        f"frontmatter name is {fm['name']!r} but the directory is "
        f"{pathlib.Path.cwd().name!r}. A client that enforces the spec will "
        "reject the skill, so either rename the directory or the field."
    )


def test_the_description_is_within_the_limit(fm: dict[str, str]) -> None:
    n = len(fm["description"])
    assert 1 <= n <= 1024, f"description is {n} characters, the limit is 1024"


# ── optional fields, when present ─────────────────────────────────────


def test_no_field_outside_the_spec(fm: dict[str, str]) -> None:
    extra = set(fm) - ALLOWED
    assert not extra, f"frontmatter fields the spec does not define: {sorted(extra)}"


def test_compatibility_is_within_the_limit(fm: dict[str, str]) -> None:
    if "compatibility" in fm:
        n = len(fm["compatibility"])
        assert 1 <= n <= 500, f"compatibility is {n} characters, the limit is 500"


def test_the_declared_license_matches_the_bundled_one(fm: dict[str, str]) -> None:
    # A frontmatter license that disagrees with LICENSE is worse than none.
    if "license" in fm:
        assert fm["license"].split()[0] in pathlib.Path("LICENSE").read_text()


# ── progressive disclosure ────────────────────────────────────────────


def test_skill_md_stays_under_500_lines() -> None:
    # The whole body loads the moment the skill activates, so its length is a
    # cost paid on every use. The spec recommends 500 lines and moving detail
    # into references/.
    lines = len(SKILL.read_text().splitlines())
    assert lines <= 500, f"SKILL.md is {lines} lines; move detail into references/"


def test_every_referenced_file_exists_and_is_one_level_deep() -> None:
    # The spec asks for relative paths from the skill root, one level deep. A
    # reference the agent cannot open is a dead end mid-task.
    text = SKILL.read_text()
    for path in sorted(
        set(re.findall(r"`((?:references|scripts|assets)/[A-Za-z0-9_./-]+)`", text))
    ):
        assert pathlib.Path(path).exists(), f"SKILL.md points at {path}, which is missing"
        assert path.count("/") == 1, f"{path} is deeper than one level"


def test_the_optional_directories_are_the_ones_the_spec_names() -> None:
    # scripts/, references/ and assets/ are the spec's conventions. This skill
    # uses the first two.
    assert pathlib.Path("scripts").is_dir()
    assert pathlib.Path("references").is_dir()
