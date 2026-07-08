# Roadmap

_Last updated: 2026-06-23. This is the canonical product roadmap — the real-estate
re-angle supersedes the prior general-newsletter direction._

## Thesis

Narrow hard to **real estate**. A single vertical turns on the things a general
tool can't have: transfer (shared domain priors), cold-start (sane defaults before
any user data), and stronger generation (prompts grounded in one domain). It also
activates the co-founder's real-estate network — so **marketing and tech point the
same way** instead of diverging.

The build order below is dependency-ordered: each phase exists to unlock the next.
Don't skip ahead — later phases are worthless without the data the earlier ones
collect.

---

## Phase 1 — Re-angle the site to real estate

- **Do:** Re-position the entire site/product to real estate. Narrow hard — copy,
  examples, positioning, onboarding all speak to one audience.
- **Why:** Unlocks transfer, cold-start, and better generation. Activates the
  co-founder's network. Aligns marketing with tech.
- **Exit:** Site reads as a real-estate product end to end; first network intros land.

## Phase 2 — Integrate 3 ESPs

- **Do:** Integrate the **three ESPs the beta users already use** — not a generic
  platform, just the three that cover the cohort.
- **Why:** Fastest path to **real outcome data** (opens, clicks, sends) across the
  whole beta cohort, not just the subset on one provider. Three covers the spread
  without turning into an integrations platform.
- **Exit:** Outcome data from real sends flowing in across all three, covering the
  full beta cohort.

## Phase 3 — Ship strong real-estate prompted generation

- **Do:** Ship high-quality real-estate copy generation. **Prompted only — no
  training.**
- **Why:** Proves people want the copy before spending a dollar on training.
  Validates demand with the cheapest possible build.
- **Exit:** Users generate, send, and come back for the copy. Demand signal is real.

## Phase 4 — Per-agent notebook from logged outcomes

- **Do:** Build the per-agent "notebook" from logged generation + outcome data.
- **Why:** This is how the **training data** gets collected — structured, per-agent,
  tied to real outcomes.
- **Exit:** Clean, growing dataset of (prompt → copy → outcome) per agent.

## Phase 5 — Batch fine-tune a real-estate model

- **Do:** Once enough data exists, **batch fine-tune** a real-estate-specialized model.
- **Why:** Turns the dataset into **Canadian-owned specialized IP** — a moat, and a
  strong story for grants.
- **Exit:** Fine-tuned model measurably beats the prompted baseline on real-estate copy.

## Phase 6 — Move to CLaaS (continuous learning)

- **Do:** Graduate from batch fine-tuning to **continuous learning** (CLaaS) — the
  model improves from ongoing outcomes.
- **Why:** Only worth it **once the batch version proves signal.** Continuous learning
  on an unproven model is wasted effort.
- **Exit:** Model improves on a rolling basis from live outcome data.

## Phase 7 — Clone to the next niche

- **Do:** Repeat the playbook in the next vertical.
- **Why:** By now the path (re-angle → ESP → prompted → notebook → fine-tune → CLaaS)
  is **repeatable**. Real estate proved it; the next niche is execution, not discovery.
- **Exit:** Second niche live on the same playbook.

---

## Dependency chain (why the order is fixed)

```
1 re-angle ──► 2 ESP ──► 3 prompted gen ──► 4 notebook ──► 5 batch fine-tune ──► 6 CLaaS ──► 7 clone
   (focus)      (data)     (demand)          (training      (owned IP /          (compound   (repeat)
                                              data)          grants)              learning)
```

- No outcome data without an **ESP** (2).
- No training data without **demand + logging** (3 → 4).
- No fine-tune without the **dataset** (4 → 5).
- No continuous learning until **batch proves signal** (5 → 6).
- No cloning until the **playbook is proven** once (→ 7).
