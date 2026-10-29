# The policy ladder, checked by proof

`Ladder.tla` models the DMARC policy ladder in
`engine/dmarc/policy_engine.py`: what a domain publishes, what its senders are
doing, and the one piece of advice the tool gives. TLC walks every reachable
combination and checks nine rules against all of them.

This exists because the ladder produced three bugs in two days, and every one
lived in a transition no test happened to use:

- an advance that handed back a weaker record than the one published
- relief that claimed there was no lower rung when there was one
- relief that skipped a rung and acted on five times more mail

A test proves one example. This proves every reachable one.

## Run it

```sh
mkdir -p .tla && curl -fsSL -o .tla/tla2tools.jar \
  https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar
just verify
```

TLC is one jar. Fetch it once into `.tla/`, which git ignores, or set
`TLA2TOOLS` to a copy you already have. A clean run ends with `Model checking
completed. No error has been found.` after 41 distinct states. A broken rule
names itself and exits non-zero.

`just verify` is not part of `just check` and cannot be. It needs Java and a
jar this repo does not carry, and rule 13 keeps the skill at zero
dependencies. Run it by hand whenever you change `LADDER`, `_ladder_index`,
`_relief_index`, or `dmarc_decision`.

`view.ts` is for drawing the reachable states as a chart rather than checking
them. It is the view module of the `statechart` tool and needs that tool. The
rules above do not.

### What runs in the suite

`tests/test_formal_ladder_matches_code.py` runs with every `just check`, needs
neither Java nor the network, and holds the spec against the code. It fails if
the rungs in `Ladder.tla` stop matching `LADDER`, if `Rank` stops matching
`_strength`, if the model starts admitting a policy that is not on the ladder,
if `Pcts` stops exploring percentages between the rungs, or if a rule is
defined in the spec but missing from `Ladder.cfg`. The last one matters most:
an unlisted rule is not checked, and the run still reports that the others
hold, which reads exactly like a pass.

## The nine rules

| rule | the sentence behind it |
|---|---|
| `AdvanceAlwaysStrengthens` | a step forward never hands me a weaker record |
| `ReliefAlwaysWeakens` | relief never acts on more mail than I publish now |
| `ReliefOfferedWheneverOneExists` | while my mail is blocked I am never told there is no lever, unless there is none |
| `MovesOneRung` | a step never jumps a rung |
| `AdviceIsNeverANoOp` | advice never hands back the record I already publish |
| `LadderIndexIsMonotone` | a stronger record is never counted as a lower rung than a weaker one |
| `NeverTightenWhileBleeding` | while my mail is blocked I am never told to tighten |
| `NoDeadlock` | no state the owner cannot act from |
| `EventuallyFullyProtected` | with clean senders, following the advice reaches full enforcement |

## Make sure it can still fail

A model that cannot find a bug proves nothing. Before trusting a clean run,
break the code on purpose and check the model catches it. Replacing the
`Passed` branch of `LadderIndex` with the first rung of the policy, which is
what the code did before the fix, breaks `AdvanceAlwaysStrengthens` at
`quarantine` 75 with a zero-step path.

## What it leaves out

The record, the ladder and three sender conditions. It does **not** model
several senders separately, the domain-wide versus single-source split that
decides whether the lever is offered at all, the SPF findings, or the
`_UNCONTROLLABLE` tags that stop a recipient-side gateway holding the policy
back. A bug in any of those is outside what a clean run here proves.

One difference is deliberate. `Rank` answers 2, the value for `reject`, for a
policy it does not name, while `_strength` answers 0 for a policy it does not
know. The two agree only while the model admits no policy beyond the three on
the ladder, so the suite pins that rather than the ranking alone.
