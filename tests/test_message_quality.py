"""A finding's message is the product. These rules hold it to that.

Every check returns a `message`, and that sentence is what a marketer reads and
acts on. Nothing guarded it, so machine output leaked into it: a Python list
printed as `['commerce-cta', 'financial-promise', 'urgency']`, the formula
`budget 2 = max(2, words/125)`, and `subject variant 0:` in front of a sentence
about a subject line the sender only wrote once.

Rule 12 says describe a finding in the part of the composer the user sees, and
rule 9 says a message a user can see says what to do next. Neither can be
checked by a machine. These three can, and all three are what actually broke:

1. A container interpolated into a message renders as its Python repr.
2. A formula or an internal threshold belongs in `details`, never in a sentence.
3. No dash in text a user reads.

Prose quality is still a person's judgement. This stops the regressions that
need no judgement to spot.
"""

from __future__ import annotations

import ast
import pathlib
import re

import pytest

from engine.parse import parse_eml
from engine.runner import audit
from tests.conftest import load

ENGINE = pathlib.Path(__file__).parent.parent / "engine"

# A call to one of these always renders as a Python repr inside an f-string.
_CONTAINER_CALLS = {"sorted", "list", "set", "tuple", "dict"}
_CONTAINER_METHODS = {"keys", "values", "items"}

# The notation that belongs in `details`. `cap`, `budget` and a bare
# comparison are the three that reached users.
_FORMULA = re.compile(
    r"max\(|min\(|/\s*\d{2,}|\bcap \d|\bbudget \d|\(>\d|>\d+ absolute|<= ?\d|\babs\("
)
_DASHES = (chr(0x2014), chr(0x2013))  # em dash, en dash

# A whole Python container repr, not a stray bracket. A message can quote a line
# of the sender's own body, and that line may itself hold a bracket next to a
# quote, so matching those two characters alone reported a defect that was not
# there. This still matches a body line that happens to read like a list, for
# example `prices['USD']`. A fixture carrying one would fail here and the fix
# would be to narrow this further, not to loosen it.
_QUOTED = r"""(?:'[^']*'|"[^"]*")"""
_CONTAINER_REPR = re.compile(rf"[\[{{]{_QUOTED}(?:,\s*{_QUOTED})*[\]}}]")

# A Python value printed into a sentence, as `adversarial=True` was. A sender
# cannot act on it, and it names an internal variable at the same time.
_PY_VALUE = re.compile(r"\w+=(?:True|False|None)\b")


_FUNC = ast.FunctionDef | ast.AsyncFunctionDef


def _list_returning(tree: ast.Module) -> set[str]:
    """Every function in the module whose annotation says it returns a container.

    `dkim_domains = _dkim_signing_domains(email)` holds a list, and the name
    alone does not say so. The annotation on the helper does.
    """
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, _FUNC) and isinstance(node.returns, ast.Subscript):
            value = node.returns.value
            if isinstance(value, ast.Name) and value.id in _CONTAINER_CALLS:
                names.add(node.name)
    return names


def _container_locals(func: ast.AST, list_returning: set[str]) -> set[str]:
    """Names assigned a container inside this function."""
    names = set()
    for node in ast.walk(func):
        if not isinstance(node, ast.Assign | ast.AnnAssign):
            continue
        value = node.value
        if value is None:
            continue
        held = _is_container(value) or (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id in list_returning
        )
        if not held:
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            if isinstance(target, ast.Name):
                names.add(target.id)
    return names


Message = tuple[pathlib.Path, int, str, list[ast.expr], set[str]]


def _collect(
    node: ast.AST,
    path: pathlib.Path,
    holders: set[str],
    list_returning: set[str],
    found: list[Message],
) -> None:
    """Descend from `node`, carrying the container-holding names in scope."""
    if isinstance(node, _FUNC):
        holders = holders | _container_locals(node, list_returning)
    if isinstance(node, ast.Call):
        for kw in node.keywords:
            if kw.arg != "message":
                continue
            text, exprs = _render(kw.value)
            if text is not None:
                found.append((path, kw.value.lineno, text, exprs, holders))
    for child in ast.iter_child_nodes(node):
        _collect(child, path, holders, list_returning, found)


def _messages() -> list[Message]:
    """Every `message=` the engine builds, as (file, line, template,
    interpolations, the local names in scope that hold a container).

    A message built from a plain string or an f-string is read here. One passed
    in as a variable is not, so this is a floor on the real count, not a ceiling.
    """
    found: list[Message] = []
    for path in sorted(ENGINE.rglob("*.py")):
        tree = ast.parse(path.read_text())
        _collect(tree, path, set(), _list_returning(tree), found)
    assert len(found) > 100, f"only {len(found)} messages found: the scan is broken"
    return found


def _render(node: ast.expr) -> tuple[str | None, list[ast.expr]]:
    """A message as a template: literal parts kept, each interpolation as `{}`."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value, []
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        exprs: list[ast.expr] = []
        for piece in node.values:
            if isinstance(piece, ast.Constant) and isinstance(piece.value, str):
                parts.append(piece.value)
            elif isinstance(piece, ast.FormattedValue):
                parts.append("{}")
                exprs.append(piece.value)
        return "".join(parts), exprs
    if isinstance(node, ast.IfExp):
        # A message that picks one of two sentences. Both are product text, so
        # both are read, joined by a newline so no rule matches across them.
        body, body_exprs = _render(node.body)
        orelse, orelse_exprs = _render(node.orelse)
        if body is None or orelse is None:
            return None, []
        return f"{body}\n{orelse}", body_exprs + orelse_exprs
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, left_exprs = _render(node.left)
        right, right_exprs = _render(node.right)
        if left is None or right is None:
            return None, []
        return left + right, left_exprs + right_exprs
    return None, []


def _is_container(expr: ast.expr) -> bool:
    if isinstance(expr, ast.List | ast.Set | ast.Dict | ast.ListComp | ast.SetComp | ast.DictComp):
        return True
    if isinstance(expr, ast.Call):
        func = expr.func
        if isinstance(func, ast.Name) and func.id in _CONTAINER_CALLS:
            return True
        if isinstance(func, ast.Attribute) and func.attr in _CONTAINER_METHODS:
            return True
    return False


def _holds_container(expr: ast.expr, holders: set[str]) -> bool:
    return isinstance(expr, ast.Name) and expr.id in holders


def test_no_message_interpolates_a_container() -> None:
    """`f"...: {sorted(x)}"` puts `['a', 'b']` in front of a marketer.

    A plain name counts too. `{dkim_domains}` printed `['mailer.example']` for
    a year because the name says nothing about what it holds, so the scan reads
    what the name was assigned in the same function.
    """
    bad = [
        f"{p.relative_to(ENGINE.parent)}:{line}  {text[:70]}"
        for p, line, text, exprs, holders in _messages()
        if any(_is_container(e) or _holds_container(e, holders) for e in exprs)
    ]
    assert not bad, (
        "a message renders a Python container:\n  "
        + "\n  ".join(bad)
        + (
            "\n\nRender the values as prose with engine.prose.listed, and keep the "
            "list itself in `details`."
        )
    )


def test_no_message_carries_a_formula_or_a_threshold() -> None:
    """A sender cannot act on `max(2, words/125)`. Say the number it produced."""
    bad = [
        f"{p.relative_to(ENGINE.parent)}:{line}  {text[:70]}"
        for p, line, text, _, _h in _messages()
        if _FORMULA.search(text)
    ]
    assert not bad, (
        "a message carries a formula or a threshold:\n  "
        + "\n  ".join(bad)
        + ("\n\nSay what it means for this message, and keep the number in `details`.")
    )


def test_no_message_uses_a_dash() -> None:
    """Rule 12. A comma, a colon or a period instead."""
    bad = [
        f"{p.relative_to(ENGINE.parent)}:{line}  {text[:70]}"
        for p, line, text, _, _h in _messages()
        if any(d in text for d in _DASHES)
    ]
    assert not bad, "a message uses an em or en dash:\n  " + "\n  ".join(bad)


@pytest.mark.parametrize("fixture", ["clean_bulk.eml", "broken_bulk.eml"])
async def test_no_rendered_message_shows_a_python_container(fixture: str) -> None:
    """The static scan cannot see a message built from a variable, so read the
    real report too. This is the check that would have caught the DKIM and
    reply address findings, which interpolate a plain name holding a list."""
    report = await audit(parse_eml(load(fixture)), domain_health=False)
    bad = [
        f"{f.check}: {f.message[:90]}" for f in report.findings if _CONTAINER_REPR.search(f.message)
    ]
    assert not bad, "a rendered message shows a Python container:\n  " + "\n  ".join(bad)


@pytest.mark.parametrize("fixture", ["clean_bulk.eml", "broken_bulk.eml"])
async def test_no_rendered_message_shows_a_python_value(fixture: str) -> None:
    """`Hidden-text patterns detected (1 hit(s); adversarial=True).` told a
    sender nothing it could act on. Say which of the two cases it is."""
    report = await audit(parse_eml(load(fixture)), domain_health=False)
    bad = [f"{f.check}: {f.message[:90]}" for f in report.findings if _PY_VALUE.search(f.message)]
    assert not bad, (
        "a rendered message shows a Python value:\n  "
        + "\n  ".join(bad)
        + ("\n\nSay what it means in words, and keep the value in `details`.")
    )
