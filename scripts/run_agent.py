# scripts/run_agent.py — CLI: run the full agent on a single brief.
#
# Usage (intended):
#   python scripts/run_agent.py --brief path/to/brief.md \
#       [--max-iters 4] [--score-threshold 9] [--out dir/]
#
# Thin wrapper around src/main.py::run_agent. Prints the final payload as
# JSON to stdout and writes HTML + plain-text artifacts to --out.
#
# For batch evaluation over many briefs, use eval/run_eval.py instead.
