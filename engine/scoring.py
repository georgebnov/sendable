"""Two-stage hurdle scoring pipeline.

Stage 1 — hard gates: any CRITICAL or `hard_gate=True` finding short-
circuits to NO_GO with score floored at 30. The full continuous calc
still runs for diagnostics (sub-scores stay populated), but the verdict
and final composite are forced.

Stage 2 — continuous score:
  1. Findings auto-tagged with `category` based on `check` prefix
     (or explicit override on the Finding).
  2. Findings sharing a `family` collapse to highest severity
     (one_shot semantics — see Rspamd's `one_shot=true`).
  3. Per-category penalties summed from severity deductions, clamped
     to that category's `_BUDGET` (Rspamd `max_score` analog).
  4. Per-category sub-score = 100 × (1 − capped_penalty / budget).
  5. Composite = weighted geometric mean of sub-scores.
  6. Soft multiplicative penalties applied to composite.

Verdict bands grounded in Validity 2018 Sender Score benchmark cliffs:
  GO       ≥ 85  (>80% Gmail inbox placement band)
  REVIEW   70–84 (transition band)
  NO_GO    < 70  (Return Path "cliff" — ~45% inbox)

Per-category weights anchored to the doc's research synthesis:
  Authentication 0.30 · Infrastructure 0.25 · Content 0.20
  Domain Records 0.15 · Engagement 0.10
Engagement weight redistributed proportionally if `drift.*` history
isn't present (typical for one-off audits).
"""

from __future__ import annotations

import math
from collections.abc import Callable

from .report import Finding
from .severity import SCORE_GO_MIN, SCORE_REVIEW_MIN, Severity

# ─── Category routing ───────────────────────────────────────────────────

_CATEGORY_BY_PREFIX: tuple[tuple[str, str], ...] = (
    # Authentication: receiver-reported auth + alignment
    ("auth.", "authentication"),
    # Domain records: published TXT records that configure auth/policy
    ("spf_record.", "domain_records"),
    ("dmarc_record.", "domain_records"),
    ("dkim_record.", "domain_records"),
    ("mta_sts.", "domain_records"),
    ("tlsrpt.", "domain_records"),
    ("bimi.", "domain_records"),
    # Infrastructure: live network probes against sender domain
    ("smtp.", "infrastructure"),
    ("blacklist.", "infrastructure"),
    ("url_reputation.", "infrastructure"),
    ("dns.", "infrastructure"),
    ("http.", "infrastructure"),
    ("https.", "infrastructure"),
    # Hygiene: per-email technical payload (deliverability-affecting).
    # Required headers, plain-text alt, unsubscribe, attachments, text/image
    # ratio, render quality, message size, Microsoft EOP compauth signals.
    ("content.", "hygiene"),
    ("headers.", "hygiene"),
    ("microsoft_eop.", "hygiene"),
    ("render.", "hygiene"),
    ("size.", "hygiene"),
    # Copywriting: prose quality (subject, preheader, body, reading level).
    # Soft signal — doesn't affect delivery but affects engagement. Separate
    # axis from hygiene so clean deliverable content with so-so prose can't
    # bottom out the overall score.
    ("copywriting.", "copywriting"),
    # Engagement: history-derived drift checks
    ("drift.", "engagement"),
    # Delivery placement (Gmail spam folder etc.) — infra-tier
    ("delivery.", "infrastructure"),
)

CATEGORY_WEIGHTS: dict[str, float] = {
    "authentication": 0.30,
    "infrastructure": 0.25,
    "hygiene": 0.15,
    "copywriting": 0.10,  # softest axis — affects engagement, not delivery
    "domain_records": 0.15,
    "engagement": 0.05,
}

CATEGORY_BUDGETS: dict[str, int] = {
    "authentication": 30,
    "infrastructure": 30,
    "hygiene": 20,  # tighter — hygiene defects clearly hurt delivery
    "copywriting": 50,  # wider — see _category_subscore for diminishing-returns
    "domain_records": 25,
    "engagement": 20,
}

SEVERITY_PENALTY: dict[Severity, int] = {
    Severity.CRITICAL: 0,  # hard-gate handled separately; no continuous deduct
    Severity.HIGH: 15,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

# Severity ordering for `family` dedup (highest wins).
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

HARD_GATE_FLOOR = 30
SPAM_SCORE_CAP = 50  # Mirror runner.py's existing constant for in_spam path


def _categorize(finding: Finding) -> str:
    """Resolve a Finding to its category — explicit override wins, then
    longest-matching prefix from the routing table."""
    if finding.category:
        return finding.category
    matches = [
        (prefix, cat) for prefix, cat in _CATEGORY_BY_PREFIX if finding.check.startswith(prefix)
    ]
    if not matches:
        return "infrastructure"
    matches.sort(key=lambda x: -len(x[0]))
    return matches[0][1]


def _is_hard_gate(finding: Finding) -> bool:
    """A finding triggers a hard gate when it has explicit `hard_gate=True`
    or it is a failing CRITICAL."""
    if finding.hard_gate and not finding.passed:
        return True
    return finding.severity is Severity.CRITICAL and not finding.passed


# ─── Soft multipliers ───────────────────────────────────────────────────
# Each entry: (label, predicate over findings → bool, factor).
# Applied after composite is computed. Compounds multiplicatively.


def _has_check(findings: list[Finding], check_id: str, *, failing_only: bool = True) -> bool:
    for f in findings:
        if f.check != check_id:
            continue
        if failing_only and f.passed:
            continue
        return True
    return False


SOFT_MULTIPLIERS: list[tuple[str, Callable[[list[Finding]], bool], float]] = [
    (
        "dmarc_p_none",
        lambda fs: (
            _has_check(fs, "auth.dmarc_policy_strength")
            or _has_check(fs, "dmarc_record.policy_enabled")
        ),
        0.92,
    ),
    (
        "no_mta_sts",
        lambda fs: _has_check(fs, "mta_sts.published"),
        0.97,
    ),
    (
        "no_tlsrpt",
        lambda fs: _has_check(fs, "tlsrpt.published"),
        0.97,
    ),
    (
        "generic_ptr",
        lambda fs: _has_check(fs, "sending_ip.fcrdns"),
        0.95,
    ),
]


# ─── Family dedup ───────────────────────────────────────────────────────


def _dedup_families(findings: list[Finding]) -> list[Finding]:
    """Collapse failing findings sharing a `family` into the highest-
    severity representative. Findings without a family pass through
    unchanged. Passing findings always pass through (used for visibility)."""
    by_family: dict[str, Finding] = {}
    out: list[Finding] = []
    for f in findings:
        if not f.family or f.passed:
            out.append(f)
            continue
        existing = by_family.get(f.family)
        if existing is None or _SEVERITY_RANK[f.severity] > _SEVERITY_RANK[existing.severity]:
            by_family[f.family] = f
    out.extend(by_family.values())
    return out


# ─── Continuous score ───────────────────────────────────────────────────


def _category_subscore(category: str, penalty_sum: int) -> int:
    """Map a category's summed penalty to a 0-100 sub-score.

    Most categories use the legacy additive-with-budget model: score is
    100 × (1 − min(penalty, budget) / budget). Past the budget the score
    pins to zero — which is the right behaviour for deliverability axes
    where many findings really does mean 'undeliverable'.

    Copywriting is special. It's prose advice, not a delivery factor —
    and ten soft 'subject is too long' / 'reading level high' findings
    shouldn't bottom out the whole category to zero. We use a diminishing-
    returns curve there: each penalty point hurts ~0.7 of the previous one,
    and we floor at 30. So an email with many soft copywriting flags ends
    up in the 30-50 range — visibly imperfect but not falsely catastrophic.
    """
    if category == "copywriting":
        # Each penalty point trims ~0.7 of a score-point, capped at 70 trim
        # total, then floored at 30. So:
        #   penalty=0    → 100
        #   penalty=10   → 93
        #   penalty=30   → 79
        #   penalty=60   → 58
        #   penalty=80+  → 44 (≈ floor band)
        #   penalty=200  → 30 (floor)
        trimmed = min(70, int(penalty_sum * 0.7))
        return max(30, min(100, 100 - trimmed))
    budget = CATEGORY_BUDGETS[category]
    capped = min(penalty_sum, budget)
    return max(0, min(100, round(100 * (1 - capped / budget))))


def _composite_geometric(sub_scores: dict[str, int], present: set[str]) -> int:
    """Weighted geometric mean over present categories.
    Renormalises weights when a category is absent (e.g. no drift)."""
    if not present:
        return 100
    total_weight = sum(CATEGORY_WEIGHTS[c] for c in present)
    log_score = 0.0
    for cat in present:
        s = max(1, sub_scores[cat])  # log-zero protection
        log_score += (CATEGORY_WEIGHTS[cat] / total_weight) * math.log(s)
    return max(0, min(100, round(math.exp(log_score))))


# ─── Public API ─────────────────────────────────────────────────────────


def score_findings(
    findings: list[Finding],
    *,
    in_spam: bool = False,
) -> dict:
    """Run the full 2-stage pipeline. Returns dict:
    score, verdict, sub_scores, hard_gates_failed, soft_multipliers_applied
    """
    deduped = _dedup_families(findings)

    # ─── Stage 1: hard gates ────────────────────────────────────────
    hard_gates_failed = [f.check for f in deduped if _is_hard_gate(f)]

    # ─── Stage 2: per-category continuous score ─────────────────────
    penalty_by_category: dict[str, int] = {}
    seen_categories: set[str] = set()
    for f in deduped:
        cat = _categorize(f)
        seen_categories.add(cat)
        if f.passed:
            continue
        if f.severity is Severity.CRITICAL:
            # CRITICAL is hard-gate; don't double-count in continuous penalty.
            continue
        penalty_by_category[cat] = penalty_by_category.get(cat, 0) + SEVERITY_PENALTY[f.severity]

    # Engagement collapses to "skipped" if no drift findings appeared.
    if "engagement" not in seen_categories:
        present = {c for c in CATEGORY_WEIGHTS if c != "engagement"}
    else:
        present = set(CATEGORY_WEIGHTS.keys())

    sub_scores: dict[str, int] = {}
    for cat in present:
        pen = penalty_by_category.get(cat, 0)
        sub_scores[cat] = _category_subscore(cat, pen)

    composite = _composite_geometric(sub_scores, present)

    # ─── Soft multipliers ───────────────────────────────────────────
    multipliers_applied: list[str] = []
    for label, predicate, factor in SOFT_MULTIPLIERS:
        try:
            if predicate(deduped):
                composite = round(composite * factor)
                multipliers_applied.append(label)
        except Exception:
            pass

    # ─── Hard gate / spam folder enforcement ────────────────────────
    if in_spam:
        composite = min(composite, SPAM_SCORE_CAP)
    if hard_gates_failed:
        composite = min(composite, HARD_GATE_FLOOR)
        verdict = "NO_GO"
    else:
        verdict = (
            "GO"
            if composite >= SCORE_GO_MIN
            else "REVIEW"
            if composite >= SCORE_REVIEW_MIN
            else "NO_GO"
        )

    return {
        "score": max(0, min(100, composite)),
        "verdict": verdict,
        "sub_scores": sub_scores,
        "hard_gates_failed": hard_gates_failed,
        "soft_multipliers_applied": multipliers_applied,
    }
