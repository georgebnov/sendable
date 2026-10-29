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

from engine.dmarc.policy_engine import LADDER, _strength

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
@pytest.mark.parametrize(
    "rule",
    [
        "AdvanceAlwaysStrengthens",
        "ReliefAlwaysWeakens",
        "ReliefOfferedWheneverOneExists",
        "MovesOneRung",
        "AdviceIsNeverANoOp",
        "LadderIndexIsMonotone",
        "NeverTightenWhileBleeding",
    ],
)
def test_every_rule_is_defined_and_checked(rule: str) -> None:
    """A rule defined but left out of the config is not checked, and the report
    still says the others hold. That reads like a pass."""
    assert re.search(rf"^{rule} ==", SPEC.read_text(), re.M), f"{rule} is not defined"
    assert f"INVARIANT {rule}" in CONFIG.read_text(), f"{rule} is not in the config"


def test_the_liveness_property_is_checked_too() -> None:
    assert "PROPERTY EventuallyFullyProtected" in CONFIG.read_text()
