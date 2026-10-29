"""The TLA+ model describes this repository's ladder, not a remembered one.

`tests/formal/Ladder.tla` proves nine rules about the policy ladder across every
reachable state. That proof is worth nothing the moment the spec and the code
disagree, and nothing in the suite runs TLC: it needs Java and a jar this repo
does not carry, which rule 13 keeps out. `just verify` runs it by hand.

So the suite checks the one thing that makes the proof transferable. The rungs
in the spec, the policy ranking it compares them with, and the percentages it
explores all have to match the code. A change to `LADDER` that forgets the spec
fails here rather than silently leaving a model that proves things about a
ladder this repo no longer has.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from engine.dmarc.policy_engine import (
    LADDER,
    DmarcRecord,
    _ladder_index,
    _relief_index,
    _strength,
)

SPEC = pathlib.Path(__file__).parent / "formal" / "Ladder.tla"
CONFIG = pathlib.Path(__file__).parent / "formal" / "Ladder.cfg"


def _rungs_in_spec() -> list[tuple[str, int]]:
    text = SPEC.read_text()
    block = re.search(r"^Ladder ==(.*?)>>\s*$", text, re.S | re.M)
    assert block, "the spec has no Ladder definition"
    return [
        (policy, int(pct)) for policy, pct in re.findall(r'<<"([a-z]+)",\s*(\d+)>>', block.group(1))
    ]


def test_the_spec_has_the_same_rungs_in_the_same_order() -> None:
    assert _rungs_in_spec() == LADDER, (
        "tests/formal/Ladder.tla no longer describes LADDER. Update the spec and "
        "re-run it, or the proof covers a ladder this repo does not have."
    )


def _policies_the_model_starts_from() -> set[str]:
    init = re.search(r"policy \\in \{([^}]*)\}", SPEC.read_text())
    assert init, "the spec no longer says which policies it starts from"
    return set(re.findall(r'"([a-z]+)"', init.group(1)))


def _rank_in_spec() -> dict[str, int]:
    """Read `Rank` out of the spec, with its `OTHER` arm resolved.

    `Rank` is a CASE with named arms and one `OTHER`. `OTHER` covers every
    policy the model admits that no arm names, so the map is only meaningful
    together with the policies `Init` allows."""
    block = re.search(r"Rank\(p\) ==(.*?)\n\n", SPEC.read_text(), re.S)
    assert block, "the spec has no Rank definition"
    named = {p: int(n) for p, n in re.findall(r'p = "([a-z]+)"\s*->\s*(\d+)', block.group(1))}
    other = re.search(r"OTHER\s*->\s*(\d+)", block.group(1))
    ranks = dict(named)
    if other:
        for policy in _policies_the_model_starts_from() - set(named):
            ranks[policy] = int(other.group(1))
    return ranks


def test_the_model_starts_from_exactly_the_policies_in_the_ladder() -> None:
    """`Rank`'s `OTHER` arm answers 2, which is reject. The code answers 0 for a
    policy it does not know. They agree only while the model admits no policy
    beyond the three in `LADDER`, so that is the thing to pin."""
    assert _policies_the_model_starts_from() == {p for p, _ in LADDER}


def test_the_spec_ranks_the_policies_the_way_the_code_does() -> None:
    """`Rank` is `_strength`'s first element. If they part, every comparison the
    proof makes about strength is about a different ordering than the code's."""
    spec_ranks = _rank_in_spec()
    assert spec_ranks, "no arm of Rank could be read"
    for policy, rank in sorted(spec_ranks.items()):
        assert _strength(policy, 100)[0] == rank, (
            f"the spec ranks {policy} as {rank}, the code as "
            f"{_strength(policy, 100)[0]}. Every strength comparison in the "
            f"proof is then about a different ordering."
        )


def test_the_spec_explores_percentages_that_are_not_rungs() -> None:
    """The three bugs this model exists for all lived between rungs. A Pcts set
    containing only rung values would walk straight past them."""
    found = re.search(r"Pcts == \{([^}]*)\}", SPEC.read_text())
    assert found, "the spec no longer says which percentages it explores"
    pcts = {int(n) for n in found.group(1).split(",")}
    rung_pcts = {pct for _, pct in LADDER}
    assert pcts - rung_pcts, "every percentage in the spec sits exactly on a rung"

    # The relief bug lived below the lowest rung, where a record acts on less
    # mail than any rung does. Pin that band, not the literal value in it.
    floor = min(pct for policy, pct in LADDER if policy != "none")
    assert {p for p in pcts if 0 < p < floor}, (
        f"no percentage below the lowest rung ({floor}). That band is where the "
        f"relief bug lived, so the model would walk straight past it."
    )


# The nine rules, less two that cannot be listed here. `NoDeadlock` is TLC's
# default and appears in no config. `TypeOK` is a type invariant, not a sentence
# the reader agreed to.
def _rules_in_spec() -> list[str]:
    """Every operator defined under the spec's `The rules.` banner.

    Read out of the file rather than listed here. A list is a set of names
    somebody remembered, and the drift this guards against is the one nobody
    remembers: a rule added to the spec and left out of `Ladder.cfg` is never
    checked, and TLC still reports that the others hold, which reads exactly
    like a pass."""
    parts = SPEC.read_text().split("The rules.", 1)
    assert len(parts) == 2, "the spec no longer has a rules section"
    names = re.findall(r"^([A-Z]\w*) ==", parts[1], re.M)
    assert names, "no rule could be read out of the spec"
    return names


def _rules_in_config() -> list[str]:
    return re.findall(r"^(?:INVARIANT|PROPERTY) (\w+)", CONFIG.read_text(), re.M)


def test_every_rule_in_the_spec_is_checked_and_nothing_else_is() -> None:
    assert sorted(_rules_in_spec()) == sorted(_rules_in_config()), (
        "tests/formal/Ladder.tla and tests/formal/Ladder.cfg disagree about "
        "which rules exist. A rule in the spec and not the config is never "
        "checked, and the run still reports a pass. List it in Ladder.cfg as "
        "INVARIANT for a state rule or PROPERTY for a temporal one."
    )


def test_the_documented_rule_count_is_the_real_one() -> None:
    """AGENTS.md and tests/formal/README.md both say nine rules. A tenth rule
    that leaves the prose alone makes the prose wrong."""
    checked = _rules_in_config()
    assert len(checked) == 9, (
        f"Ladder.cfg now checks {len(checked)} rules, not nine. Say the new "
        f"number in AGENTS.md and tests/formal/README.md, and give the rule a "
        f"row in that README's table, then update this count."
    )


# ---------------------------------------------------------------------------
# The two algorithms the spec rewrites by hand, transcribed back out of
# tests/formal/Ladder.tla. The spec is 1-indexed and the code is 0-indexed.
#
# The rungs above are data, and data drift is loud. These two are logic, they
# are what `just verify` tells you to re-run the model after changing, and all
# three bugs the model exists for lived in them. Rewritten logic that nothing
# compares is the quieter drift: the proof stays green about an algorithm this
# repo no longer runs.
# ---------------------------------------------------------------------------
TOP = len(LADDER)


def _spec_ladder_index(policy: str, pct: int) -> int:
    """`LadderIndex` in Ladder.tla."""
    for i in range(1, TOP + 1):
        rung_p, rung_pct = LADDER[i - 1]
        if rung_p == policy and (policy == "none" or rung_pct == pct):
            return i
    passed = [
        i for i in range(1, TOP + 1) if LADDER[i - 1][0] == policy and LADDER[i - 1][1] <= pct
    ]
    if passed:
        return max(passed)
    same = [i for i in range(1, TOP + 1) if LADDER[i - 1][0] == policy]
    if same:
        return max(min(same) - 1, 1)
    return 1


def _spec_strength(policy: str, pct: int) -> tuple[int, int]:
    """`Strength` in Ladder.tla, built on the `Rank` read out of the spec.

    Transcribed rather than imported. `_spec_relief_index` decides which rung is
    weaker, so importing `_strength` for that would put the same function on
    both sides of the comparison and hide a drift in it. The spec's `Below` is a
    pair compared left to right, which is what Python does to a tuple, so the
    comparison itself needs no transcription."""
    rank = _rank_in_spec()[policy]
    return (rank, 0 if rank == 0 else pct)


@pytest.mark.parametrize("policy", ["none", "quarantine", "reject"])
@pytest.mark.parametrize("pct", [0, 10, 25, 50, 75, 90, 100])
def test_the_spec_measures_strength_the_way_the_code_does(policy: str, pct: int) -> None:
    """The rank alone is not enough. `Strength` breaks a tie on the percentage
    and reads it as 0 under `none`, where the percentage means nothing, and that
    tie-break is what orders two records under the same policy."""
    assert _spec_strength(policy, pct) == _strength(policy, pct), (
        f"at p={policy}, pct={pct} the spec's Strength and _strength part. "
        f"Every rule the proof states about one record acting on more mail "
        f"than another is then about a different measure."
    )


def _spec_relief_index(policy: str, pct: int) -> int | None:
    """`ReliefIndex` in Ladder.tla, with `HasRelief` as the None case."""
    weaker = [
        i for i in range(1, TOP + 1) if _spec_strength(*LADDER[i - 1]) < _spec_strength(policy, pct)
    ]
    return max(weaker) if weaker else None


@pytest.mark.parametrize("policy", ["none", "quarantine", "reject"])
@pytest.mark.parametrize("pct", [0, 10, 25, 50, 75, 90, 100])
def test_the_spec_counts_the_rung_the_way_the_code_does(policy: str, pct: int) -> None:
    rec = DmarcRecord(exists=True, p=policy, pct=pct)
    assert _spec_ladder_index(policy, pct) == _ladder_index(rec) + 1, (
        f"at p={policy}, pct={pct} the spec's LadderIndex and _ladder_index "
        f"part. Every rule the proof states about a rung is then about a "
        f"different rung than the code reads."
    )


@pytest.mark.parametrize("policy", ["none", "quarantine", "reject"])
@pytest.mark.parametrize("pct", [0, 10, 25, 50, 75, 90, 100])
def test_the_spec_finds_the_same_relief_rung_as_the_code(policy: str, pct: int) -> None:
    rec = DmarcRecord(exists=True, p=policy, pct=pct)
    code = _relief_index(rec)
    assert _spec_relief_index(policy, pct) == (None if code is None else code + 1), (
        f"at p={policy}, pct={pct} the spec's ReliefIndex and _relief_index "
        f"part. ReliefAlwaysWeakens and MovesOneRung then prove nothing about "
        f"the rollback a user is actually offered."
    )
