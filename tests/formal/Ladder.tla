---- MODULE Ladder ----
(***************************************************************************)
(* The DMARC policy ladder in engine/dmarc/policy_engine.py.               *)
(*                                                                         *)
(* A domain publishes a record: a policy and a percentage. The tool reads   *)
(* it, looks at what the reports say about the senders, and gives one piece *)
(* of advice. The owner may follow that advice, which changes the record.   *)
(* Senders break and get fixed on their own.                               *)
(*                                                                         *)
(* The percentages model real records, not only the rungs, because a record *)
(* can hold any value and the three bugs found so far all lived between     *)
(* rungs.                                                                  *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets

Pcts == {10, 25, 50, 75, 100}

\* LADDER in policy_engine.py, as <<policy, pct>> pairs, 1-indexed here.
Ladder == << <<"none", 0>>,
             <<"quarantine", 25>>, <<"quarantine", 50>>, <<"quarantine", 100>>,
             <<"reject", 25>>, <<"reject", 50>>, <<"reject", 100>> >>

Top == Len(Ladder)

Rank(p) == CASE p = "none"       -> 0
             [] p = "quarantine" -> 1
             [] OTHER            -> 2

\* _strength: how much mail a record acts on. Policy leads, percent breaks ties.
Strength(p, pc) == << Rank(p), IF Rank(p) = 0 THEN 0 ELSE pc >>

Below(a, b) == a[1] < b[1] \/ (a[1] = b[1] /\ a[2] < b[2])

\* _ladder_index: the rung this record counts as.
OnRung(i, p, pc) == Ladder[i][1] = p /\ (p = "none" \/ Ladder[i][2] = pc)
Passed(p, pc)    == { i \in 1..Top : Ladder[i][1] = p /\ Ladder[i][2] <= pc }
SamePolicy(p)    == { i \in 1..Top : Ladder[i][1] = p }

LadderIndex(p, pc) ==
  IF \E i \in 1..Top : OnRung(i, p, pc)
    THEN CHOOSE i \in 1..Top : OnRung(i, p, pc)
  ELSE IF Passed(p, pc) # {}
    THEN CHOOSE i \in Passed(p, pc) : \A j \in Passed(p, pc) : j <= i
  ELSE IF SamePolicy(p) # {}
    THEN LET f == CHOOSE i \in SamePolicy(p) : \A j \in SamePolicy(p) : i <= j
         IN IF f - 1 >= 1 THEN f - 1 ELSE 1
  ELSE 1

\* _relief_index: the highest rung acting on less mail than this record.
Weaker(p, pc) == { i \in 1..Top : Below(Strength(Ladder[i][1], Ladder[i][2]),
                                       Strength(p, pc)) }
HasRelief(p, pc) == Weaker(p, pc) # {}
ReliefIndex(p, pc) ==
  CHOOSE i \in Weaker(p, pc) : \A j \in Weaker(p, pc) : j <= i

(***************************************************************************)
(* State                                                                   *)
(*                                                                         *)
(* policy, pct   what the domain publishes                                 *)
(* senders       "clean"     every sender authenticates                    *)
(*               "unaligned" a real sender fails, nothing lost yet         *)
(*               "bleeding"  a real sender fails and the policy is          *)
(*                           blocking its mail right now                    *)
(***************************************************************************)
VARIABLES policy, pct, senders
vars == << policy, pct, senders >>

Enforcing == Rank(policy) > 0

(***************************************************************************)
(* dmarc_decision, as the cascade in the file.                             *)
(***************************************************************************)
Verdict ==
  IF senders = "bleeding"
    THEN IF HasRelief(policy, pct) THEN "ROLLBACK" ELSE "FIX_SENDER"
  ELSE IF senders = "unaligned" THEN "BLOCKED"
  ELSE IF LadderIndex(policy, pct) >= Top THEN "AT_GOAL"
  ELSE "ADVANCE"

AdviceTarget ==
  CASE Verdict = "ADVANCE"  -> Ladder[LadderIndex(policy, pct) + 1]
    [] Verdict = "ROLLBACK" -> Ladder[ReliefIndex(policy, pct)]
    [] OTHER                -> << policy, pct >>

(***************************************************************************)
(* Steps                                                                   *)
(***************************************************************************)
TheOwnerFollowsTheAdvice ==
  /\ Verdict \in {"ADVANCE", "ROLLBACK"}
  /\ policy' = AdviceTarget[1]
  /\ pct'    = IF AdviceTarget[1] = "none" THEN 100 ELSE AdviceTarget[2]
  /\ UNCHANGED senders

ASenderBreaks ==
  /\ senders = "clean"
  /\ senders' = "unaligned"
  /\ UNCHANGED << policy, pct >>

ThePolicyStartsBlockingIt ==
  /\ senders = "unaligned"
  /\ Enforcing
  /\ senders' = "bleeding"
  /\ UNCHANGED << policy, pct >>

TheSenderGetsAuthenticated ==
  /\ senders \in {"unaligned", "bleeding"}
  /\ senders' = "clean"
  /\ UNCHANGED << policy, pct >>

\* A correct end state still needs a step out, or TLC calls it a deadlock.
NothingLeftToDo ==
  /\ Verdict \in {"AT_GOAL", "FIX_SENDER"}
  /\ senders = "clean" \/ Verdict = "FIX_SENDER"
  /\ UNCHANGED vars

Init ==
  /\ policy \in {"none", "quarantine", "reject"}
  /\ pct \in Pcts
  /\ senders = "clean"

Next ==
  \/ TheOwnerFollowsTheAdvice
  \/ ASenderBreaks
  \/ ThePolicyStartsBlockingIt
  \/ TheSenderGetsAuthenticated
  \/ NothingLeftToDo

Spec == Init /\ [][Next]_vars /\ WF_vars(TheOwnerFollowsTheAdvice)

(***************************************************************************)
(* The rules. Each one is a sentence the reader agreed to.                 *)
(***************************************************************************)

\* "A step forward never hands me a weaker record than the one I publish."
AdvanceAlwaysStrengthens ==
  Verdict = "ADVANCE" =>
    Below(Strength(policy, pct), Strength(AdviceTarget[1], AdviceTarget[2]))

\* "A step offered as relief never acts on more mail than I publish now."
ReliefAlwaysWeakens ==
  Verdict = "ROLLBACK" =>
    Below(Strength(AdviceTarget[1], AdviceTarget[2]), Strength(policy, pct))

\* "While my own mail is being blocked, I am never told there is no lever
\*  unless I really am at the bottom."
ReliefOfferedWheneverOneExists ==
  (senders = "bleeding" /\ Rank(policy) > 0) => Verdict = "ROLLBACK"

\* "A step never jumps over a rung."
MovesOneRung ==
  Verdict \in {"ADVANCE", "ROLLBACK"} =>
    LET here == LadderIndex(policy, pct)
        there == IF Verdict = "ADVANCE" THEN here + 1 ELSE ReliefIndex(policy, pct)
    IN there >= here - 1 /\ there <= here + 1

\* "Advice never hands me back the record I already publish."
AdviceIsNeverANoOp ==
  Verdict \in {"ADVANCE", "ROLLBACK"} =>
    << AdviceTarget[1], IF AdviceTarget[1] = "none" THEN 100 ELSE AdviceTarget[2] >>
      # << policy, pct >>

\* "A stronger record is never counted as a lower rung than a weaker one."
LadderIndexIsMonotone ==
  \A p1, p2 \in {"none", "quarantine", "reject"} :
    \A c1, c2 \in Pcts :
      Below(Strength(p1, c1), Strength(p2, c2)) =>
        LadderIndex(p1, c1) <= LadderIndex(p2, c2)

\* "While my mail is being blocked I am never told to tighten."
NeverTightenWhileBleeding ==
  senders = "bleeding" => Verdict # "ADVANCE"

TypeOK ==
  /\ policy \in {"none", "quarantine", "reject"}
  /\ pct \in Pcts
  /\ senders \in {"clean", "unaligned", "bleeding"}

\* "If my senders stay clean, following the advice gets me to full enforcement."
EventuallyFullyProtected ==
  [](senders = "clean" => <>(Verdict = "AT_GOAL" \/ senders # "clean"))

====
