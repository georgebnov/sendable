"""CLI: generate one newsletter email.

Usage:
    python scripts/copy_gen.py --brief briefs/lambton_mills.md --sender info@iknowtoronto.com
    python scripts/copy_gen.py --sender info@iknowtoronto.com   # interactive prompt

Brief file format (one key:value per line, lines starting with # ignored):

    goal: share context on the Lambton Mills release
    audience: past buyers, Toronto
    key_message: pricing landed at mid-$1,100s per sq ft
    cta: reply
    length_hint: short
    friction_point: deposit is 20% over 18 months
    framing: project

Writes output/copy_<ts>.md with the full refine trail, and prints the final
copy in sectioned form to stdout.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from datetime import datetime, timezone
from email.utils import parseaddr
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from copy_gen import Brief, extract_voice, refine  # noqa: E402
from copy_gen.refine import RefineResult  # noqa: E402
from memory.store import history_for  # noqa: E402


_BRIEF_KEYS = {
    "goal", "audience", "key_message", "cta", "length_hint",
    "friction_point", "framing", "sign_off",
}
# `fact` is a repeatable key — every `fact: ...` line in the brief file
# appends to Brief.supporting_facts. Also accept `- fact` shorthand under
# a `supporting_facts:` section header.


def _parse_brief_file(path: Path) -> Brief:
    data: dict = {}
    facts: list[str] = []
    in_facts_section = False
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Bullet under a `supporting_facts:` section header.
        if in_facts_section and line.startswith("-"):
            item = line.lstrip("-").strip()
            if item:
                facts.append(item)
            continue
        if ":" not in line:
            in_facts_section = False
            continue
        key, _, val = line.partition(":")
        key = key.strip().lower().replace(" ", "_")
        val = val.strip()
        if key == "supporting_facts":
            in_facts_section = True
            if val:
                facts.append(val)
            continue
        in_facts_section = False
        if key == "fact" and val:
            facts.append(val)
            continue
        if key in _BRIEF_KEYS and val:
            # Allow users to encode multi-line sign-off as "line1\\nline2\\nline3".
            if key == "sign_off":
                val = val.replace("\\n", "\n")
            data[key] = val
    missing = {"goal", "audience", "key_message"} - data.keys()
    if missing:
        raise ValueError(
            f"brief file {path} missing required fields: {sorted(missing)}"
        )
    if facts:
        data["supporting_facts"] = facts
    return Brief(**data)


def _prompt_brief() -> Brief:
    def ask(label: str, default: str | None = None) -> str:
        hint = f" [{default}]" if default else ""
        val = input(f"{label}{hint}: ").strip()
        return val or (default or "")

    print("No --brief supplied. Interactive brief:", file=sys.stderr)
    goal = ask("Goal")
    audience = ask("Audience")
    key_message = ask("Key message")
    cta = ask("CTA", default="reply")
    length_hint = ask("Length (short/medium/long)", default="short")
    friction_point = ask("Friction point (optional)", default="")
    framing = ask("Framing (project/category)", default="project")

    # Sign-off: up to 3 lines. Empty line to finish. Blank overall = let
    # the generator compose one from the voice profile.
    print(
        "Sign-off (up to 3 lines — name, role + domain, phone). "
        "Press Enter on an empty line to finish. "
        "Press Enter immediately to let the generator compose one.",
        file=sys.stderr,
    )
    sign_off_lines: list[str] = []
    for i in range(3):
        line = input(f"  line {i + 1}: ").rstrip()
        if not line:
            break
        sign_off_lines.append(line)
    sign_off = "\n".join(sign_off_lines) if sign_off_lines else None

    return Brief(
        goal=goal,
        audience=audience,
        key_message=key_message,
        cta=cta or "reply",
        length_hint=length_hint or "short",
        friction_point=friction_point or None,
        framing=framing or "project",
        sign_off=sign_off,
    )


def _sender_domain(sender: str) -> str:
    _, addr = parseaddr(sender)
    if "@" not in addr:
        addr = sender
    return addr.rsplit("@", 1)[-1].lower()


def _sev_order(severity_value: str) -> int:
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(severity_value, 9)


def _format_findings(findings) -> str:
    if not findings:
        return "_(no findings)_"
    lines = []
    for f in sorted(findings, key=lambda x: _sev_order(x.severity.value)):
        lines.append(f"- **[{f.severity.value}]** `{f.check}` — {f.message}")
    return "\n".join(lines)


def _render_output_md(result: RefineResult, brief: Brief, sender: str, had_voice: bool) -> str:
    lines: list[str] = []
    lines.append(f"# Generated copy — {sender}")
    lines.append("")
    lines.append(f"- **Goal**: {brief.goal}")
    lines.append(f"- **Audience**: {brief.audience}")
    lines.append(f"- **Key message**: {brief.key_message}")
    lines.append(f"- **Length**: {brief.length_hint}")
    lines.append(f"- **Framing**: {brief.framing}")
    if brief.friction_point:
        lines.append(f"- **Friction point**: {brief.friction_point}")
    lines.append(f"- **Voice profile**: {'loaded' if had_voice else 'none — generic craft mode'}")
    lines.append(f"- **Converged**: {result.converged}")
    lines.append("")

    final = result.final_draft
    if final is None:
        lines.append("## Final copy — NOT AVAILABLE")
        lines.append("")
        lines.append("The LLM call failed in every round. See refine trail below.")
    else:
        lines.append(f"- **Story mode**: `{final.story_mode}`")
        lines.append("")
        lines.append("## Subjects (3 variants)")
        lines.append("")
        for i, subj in enumerate(final.subjects):
            mark = " **← chosen**" if i == final.chosen_subject_index else ""
            lines.append(f"{i + 1}. {subj}{mark}")
        lines.append("")
        lines.append("## Preview text")
        lines.append("")
        lines.append(f"> {final.preview}")
        lines.append("")
        lines.append("## Body")
        lines.append("")
        lines.append("```")
        lines.append(final.body_plain)
        lines.append("```")
        lines.append("")
        lines.append("## Sign-off")
        lines.append("")
        lines.append("```")
        lines.append(final.sign_off)
        lines.append("```")
        lines.append("")

    lines.append("## Refine trail")
    lines.append("")
    for r in result.rounds:
        lines.append(f"### Round {r.round_index + 1}")
        lines.append("")
        if r.draft is None:
            lines.append("_LLM call returned no draft this round._")
        else:
            lines.append(f"Draft produced ({len(r.findings)} findings).")
        lines.append("")
        lines.append(_format_findings(r.findings))
        lines.append("")
    return "\n".join(lines)


def _print_final(result: RefineResult) -> None:
    final = result.final_draft
    if final is None:
        print("\n(no final draft — LLM unavailable)\n", file=sys.stderr)
        return
    print(f"\n### Story mode: {final.story_mode}")
    print("\n### Subjects (3 variants)")
    for i, subj in enumerate(final.subjects):
        mark = "  ← chosen" if i == final.chosen_subject_index else ""
        print(f"  {i + 1}. {subj}{mark}")
    print("\n### Preview")
    print(f"  {final.preview}")
    print("\n### Body")
    print(final.body_plain)
    print("\n### Sign-off")
    print(final.sign_off)
    print()
    if not result.converged:
        print(
            "NOTE: final draft still has blocking findings (see output file "
            "for refine trail).",
            file=sys.stderr,
        )


async def _run(brief: Brief, sender: str) -> tuple[RefineResult, bool]:
    domain = _sender_domain(sender)
    history = history_for(domain, n_limit=100)
    voice = await extract_voice(history, domain)
    result = await refine(brief, voice)
    return result, voice is not None


def main() -> int:
    # Populate from .env if present so the key check below sees it.
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass
    if not os.environ.get("OPENAI_API_KEY"):
        print("copy_gen: OPENAI_API_KEY not set (export it or put it in .env)",
              file=sys.stderr)
        return 1

    parser = argparse.ArgumentParser(description="Generate one newsletter email.")
    parser.add_argument("--brief", type=Path, help="Brief file (key: value per line).")
    parser.add_argument(
        "--sender",
        help=(
            "Sender email (e.g. info@iknowtoronto.com). "
            "If omitted, you'll be prompted."
        ),
    )
    parser.add_argument(
        "--length",
        choices=("short", "medium", "long"),
        help="Override brief length_hint.",
    )
    args = parser.parse_args()

    if args.brief:
        if not args.brief.exists():
            print(f"copy_gen: brief file not found: {args.brief}", file=sys.stderr)
            return 1
        brief = _parse_brief_file(args.brief)
    else:
        brief = _prompt_brief()

    sender = args.sender
    if not sender:
        sender = input("Sender email (e.g. info@iknowtoronto.com): ").strip()
        if not sender or "@" not in sender:
            print("copy_gen: a valid sender email is required.", file=sys.stderr)
            return 1

    if args.length:
        brief = brief.model_copy(update={"length_hint": args.length})

    result, had_voice = asyncio.run(_run(brief, sender))

    output_dir = ROOT / "output"
    output_dir.mkdir(exist_ok=True)
    ts_utc = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = output_dir / f"copy_{ts_utc}.md"
    out_path.write_text(_render_output_md(result, brief, args.sender, had_voice))

    _print_final(result)
    print(f"\nWritten: {out_path}", file=sys.stderr)
    if not had_voice:
        print("Voice: generic craft mode (no profile).", file=sys.stderr)
    return 0 if result.final_draft is not None else 1


if __name__ == "__main__":
    sys.exit(main())
