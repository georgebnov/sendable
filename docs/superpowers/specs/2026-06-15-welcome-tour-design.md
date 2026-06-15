# Welcome sequence → story tour

**Date:** 2026-06-15
**Surface:** `production/frontend/app/(onboarding)/welcome/page.tsx`
**Prototype:** `.superpowers/brainstorm/47100-1781556479/content/prototype.html` (clickable, all 6 screens, real Sendable tokens)

## Problem

The current `/welcome` is a 6-step **setup wizard** (Welcome → Domain → DMARC → Audit alias → What we see → Done). It configures the product but never sells the point or the shift. It reads as a config checklist, buries the privacy answer (the #1 question users ask) at step 5, and never shows the new "Generate" capability.

## Decision

Replace the setup wizard with a **6-screen story tour**. Story-only — no setup inputs. It sells the shift, answers the privacy question up front, teaches the off-app steps with synthetic visuals, and hands off to the dashboard. (Decisions reached via the brainstorming session; see prototype.)

### Layout

Full-bleed centered slide (not the old left-sidebar step list):

- Top bar: wordmark `s` + "Sendable" + `Beta` tag, clickable progress dots (right).
- Body: two columns — copy on the left (label, headline, body), a synthetic product/how-to visual on the right. Single column under ~820px.
- Footer: `‹ Back` (hidden on first), spacer, `Skip tour` (hidden on last), primary `Next →` (becomes `Go to my dashboard →` on last).
- Light fade-up animation per slide. Arrow keys advance/retreat.

### The six screens

| # | Screen | Headline | Visual (synthetic) | Personalized data |
|---|--------|----------|--------------------|-------------------|
| 1 | Hook | Your newsletter is half your business. Make sure it lands. | inbox-lands vs. spam mock | — |
| 2 | Privacy | First — no, we don't read your email. | Google "Remove access" panel | — |
| 3 | Generate | Don't even write it yourself. | notes → audited-draft card | — |
| 4 | Audits | Know it lands before you hit send. | audit report w/ "fix these first" + how-to box | **user's `+audit` alias** |
| 5 | Domain Health | See who's sending as you. | "Your reporting address" chip + DNS TXT panel | **user's rua address + token** |
| 6 | Hand-off | That's the shift: email you can trust to land. | centered checkmark + CTA | — |

- **How-to visuals** (inline, not separate screens): screen 2 = revoking access; screen 4 = sending to `+audit`; screen 5 = DMARC DNS record.
- Each how-to screen carries a muted **"Full setup guide · Coming soon"** placeholder under the paragraph (left column, consistent ~12px gap). Blogs don't exist yet; flip each to a live link when its guide ships.
- Copy tone: warm, plain — punchy headline, calm body. Never technical on the surface.
- **No social-proof line.** One small **"Free while we're in beta"** line on the hand-off screen.

### Personalized (live) data

The tour shows the user's *real* values so setup feels half-done:

- **Screen 4** — the `+audit` alias built from their sign-in email (`local+audit@domain`), `+audit` emphasized.
- **Screen 5** — their DMARC reporting address (`<token>@ag.sndbl.com`) as a copyable chip, and the same token inside the DNS TXT panel's `rua=mailto:` value.

Data sources (read-only — no setup input, no writes during the tour):

- `GET /account` → `email` (for the alias).
- `GET /dmarc/setup` → `rua_address`, `token`, `reporting_domain`, `sending_domain` (for the rua chip + TXT panel). This is the same call the old `StepDmarc` made; it returns/generates the per-user token regardless of whether a sending domain is set.

**Fallbacks:** if `sending_domain` is null, the TXT panel host shows `_dmarc.yourdomain.com` (as the old code did). The rua address is always available from `/dmarc/setup`. If `/account` email is missing, alias falls back to `you+audit@gmail.com`.

### Behavior

- Resume via `?step=N` (keep current pattern); `Skip tour` jumps to the last screen.
- Final screen's `Go to my dashboard →` flips `onboarded_at` (PATCH `/account`) so the tour shows at most twice, then routes to `/`. (Keep the existing `finishOnboarding` mutation.)
- Visuals are synthetic mock UI — **never real test-account screenshots** (per product owner).

## Scope

**In scope:** rewrite `welcome/page.tsx` as the story tour. Frontend only — no backend, no schema, no migration. `Account` type already carries the needed fields; `DmarcSetup` type already exists. The `DmarcSetupCard` import is dropped (still used by the DMARC page).

**Out of scope — required follow-on:** a **dashboard setup-nudge** (checklist/banner: add domain, point DMARC, send first audit). Because the tour no longer forces setup, a new user finishes inspired but unconfigured; the dashboard nudge is what actually drives setup. This gets its own spec next.

**Not doing:** the marketing/landing page (separate, handled by the website creator); writing the blog/guide articles (placeholder links only).

## Testing

No frontend test runner exists in `production/frontend` (no jest/vitest/RTL). Verify via `npx tsc --noEmit` + `npx next build --no-lint`, and a manual walk of all six screens. (Rule 7 gap noted — standing up a runner is out of scope for this UI change unless requested.)
