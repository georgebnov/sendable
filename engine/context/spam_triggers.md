# Spam-trigger blocklist (real-estate compounding vocabulary)
#
# One phrase per line. Case-insensitive substring match across subject,
# preview, and body. Empty lines and lines starting with `#` are ignored.
#
# Grouped by promotional category so the critic can count DISTINCT categories
# fired in one email (compound-signal score). A single category hitting is
# noise; 3+ categories hitting is the pattern providers now quarantine.
#
# User can edit this file freely. No code change required to retune.

# ─── urgency ─────────────────────────────────────────────
prices go up
limited time
act now
don't miss out
hurry
last chance
ending soon
only today
today only
while supplies last
closing soon
sales event this weekend

# ─── fomo ────────────────────────────────────────────────
vip access
platinum access
priority registration
exclusive offer
members only
only x units left
only a few left
final units
selling fast

# ─── commerce-cta ────────────────────────────────────────
reserve your unit
reserve now
register here
sign up now
buy now
order now
click here
shop now
purchase now

# ─── financial-promise ───────────────────────────────────
guaranteed
risk-free
no obligation
free gift
free offer
100% free
cash back
huge savings
incredible savings
unbeatable price
best price guaranteed
starting from $
save up to
exclusive savings
price adjustments
save $

# ─── formatting ──────────────────────────────────────────
# These strings are literal; ALL-CAPS / multi-! / multi-? patterns are
# caught by the subject-heuristics check in critic.py, not here.
!!!
???
$$$

# ─── generic-greeting ────────────────────────────────────
dear friend
dear customer
dear sir/madam
dear valued customer
to whom it may concern

# ─── newsletter-word ─────────────────────────────────────
# The word "newsletter" in a subject line is measured as −18.7% open rate
# (Zippia). Critic flags it as LOW; not elevated higher because it also
# appears in legitimate "weekly newsletter" mailer contexts.
newsletter

# ─── pre-construction-specific ───────────────────────────
# These are the ones Toronto buyers now actively distrust post-2024.
prices and floorplans attached
floorplans attached
platinum agent
insider access
builder direct
investment opportunity
guaranteed rental
guaranteed roi
