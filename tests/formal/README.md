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
completed. No error has been found.` after 49 distinct states. A broken rule
names itself and exits non-zero.

`just verify` is not part of `just check` and cannot be. It needs Java and a
jar this repo does not carry, and rule 13 keeps the skill at zero
dependencies. Run it by hand whenever you change `LADDER`, `_ladder_index`,
`_relief_index`, or `dmarc_decision`.

### What runs in the suite

`tests/test_formal_ladder_matches_code.py` runs with every `just check`, needs
neither Java nor the network, and holds the spec against the code. It fails if
the rungs in `Ladder.tla` stop matching `LADDER`, if `Rank` stops matching
`_strength`, if the model starts admitting a policy that is not on the ladder,
if `Pcts` stops exploring percentages between the rungs, if `LadderIndex` or
`ReliefIndex` stop answering what `_ladder_index` and `_relief_index` answer,
or if a rule is defined in the spec but missing from `Ladder.cfg`.

Two of those matter most. `LadderIndex` and `ReliefIndex` are logic the spec
rewrites by hand, and all three bugs lived in them, so the suite reads both
back out of the spec and compares them against the code at every percentage on
a rung, between rungs, and below the lowest. And an unlisted rule is not
checked while the run still reports that the others hold, which reads exactly
like a pass, so the suite reads the rule names out of the spec instead of
holding a list of its own.

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
| `TypeOK` | the state never holds a policy, percentage or sender condition the model does not name |
| `EventuallyFullyProtected` | with clean senders, following the advice reaches full enforcement |

TLC also reports a deadlock, a state the owner cannot act from, on every run
without being asked. That is a default rather than a line in `Ladder.cfg`, so
`NothingLeftToDo` keeps the two correct end states out of it.

## Make sure it can still fail

A model that cannot find a bug proves nothing. Before trusting a clean run,
break the model on purpose and check it catches it. Replace the `Passed` branch
of `LadderIndex` with the first rung of the policy, which is what the code did
before the fix:

```
ELSE IF SamePolicy(p) # {}
  THEN CHOOSE i \in SamePolicy(p) : \A j \in SamePolicy(p) : i <= j
```

`just verify` then prints `Error: The invariant of LadderIndexIsMonotone is
equal to FALSE` and exits 151.

TLC stops at the first rule it finds broken, so one name is all you get. A tool
that removes each broken rule and runs TLC again, as `statechart` does, lists
every rule the same bug breaks. Expect the two to name different rules for the
same mutation.

`EventuallyFullyProtected` is the one rule the mutation above cannot reach,
because it is a liveness property rather than an invariant. It holds only
because `Spec` says the owner eventually acts. Drop that clause:

```
Spec == Init /\ [][Next]_vars
```

and TLC prints `Error: Temporal properties were violated.` and exits 13. A
liveness property that nothing can break is a line in the table that proves
nothing, so it is worth re-checking after any change to `Spec` or to the steps.

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
