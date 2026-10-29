"""A small HTML tree, built on the standard library.

The audit reads an email's HTML to answer plain questions: what text does a
reader see, which links are there, which elements are styled invisible. That
needs a tree with a handful of operations, not a full browser DOM, so this
module builds one on `html.parser` from the standard library and exposes only
what the checks use.

It exists because a skill has to run where nothing can be installed. Claude's
own code execution container has no network and no package index, so every
third-party import is a wall a user hits before the first audit.

Email HTML is bad HTML. Templates ship unclosed cells, stray closing tags and
Outlook conditional comments, so the parser never raises: it closes what it
must and keeps going, the way a mail client does.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from html import escape, unescape
from html.parser import HTMLParser

# An element that cannot contain anything, so it never opens a scope.
_VOID = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
)

# Text inside these is code, not something a reader sees.
_NON_VISIBLE = frozenset({"script", "style", "template"})

# A comment keeps its place in the markup, because a template's Outlook
# conditional blocks live in one, but it is never text a reader sees and it
# is never an element a selector can match.
_COMMENT = "#comment"


_Names = str | Iterable[str] | bool | None
_Filter = bool | re.Pattern[str]


def _attr_matches(value: str | None, wanted: _Filter) -> bool:
    """Does an attribute satisfy a filter? False means the filter is off."""
    if wanted is False:
        return True
    if not value:
        return False
    if wanted is True:
        return True
    return wanted.search(value) is not None


class Node:
    """One element, or one run of text when `tag` is None."""

    __slots__ = ("attrs", "children", "parent", "tag", "text")

    def __init__(
        self,
        tag: str | None,
        attrs: dict[str, str] | None = None,
        text: str = "",
        parent: Node | None = None,
    ) -> None:
        self.tag = tag
        self.attrs: dict[str, str] = attrs or {}
        self.children: list[Node] = []
        self.parent = parent
        self.text = text

    # ── reading ──────────────────────────────────────────────────────────

    @property
    def name(self) -> str | None:
        """The tag name, or None for a run of text. Matches the attribute the
        checks already read."""
        return self.tag

    @property
    def string(self) -> str | None:
        """The text of this element when it holds exactly one run of text.

        `<style>` and `<script>` bodies are read this way. An element holding
        anything else, or nothing, has no single string and returns None.
        """
        if len(self.children) != 1:
            return None
        only = self.children[0]
        return only.text if only.tag is None else None

    def get(self, key: str, default: str | None = None) -> str | None:
        return self.attrs.get(key, default)

    def __getitem__(self, key: str) -> str:
        return self.attrs[key]

    def __contains__(self, key: str) -> bool:
        return key in self.attrs

    def descendants(self) -> list[Node]:
        out: list[Node] = []
        stack = list(self.children)
        while stack:
            node = stack.pop(0)
            out.append(node)
            stack = node.children + stack
        return out

    def find_all(
        self,
        name: _Names = None,
        *,
        href: _Filter = False,
        style: _Filter = False,
        class_: str | None = None,
    ) -> list[Node]:
        """Every descendant element that matches.

        `name` is a tag, any collection of tags, or True for every element.
        An attribute filter is True to require the attribute at all, or a
        compiled pattern to require the value to match it. One check hunts
        hidden text by matching the style attribute against a pattern, which
        is why a pattern is allowed here.
        """
        wanted: frozenset[str] | None
        # True means "any element", the shorthand the checks use.
        if name is None or isinstance(name, bool):
            wanted = None
        elif isinstance(name, str):
            wanted = frozenset({name})
        else:
            wanted = frozenset(name)

        out = []
        for node in self.descendants():
            if node.tag is None or node.tag == _COMMENT:
                continue
            if wanted is not None and node.tag not in wanted:
                continue
            if not _attr_matches(node.attrs.get("href"), href):
                continue
            if not _attr_matches(node.attrs.get("style"), style):
                continue
            if class_ is not None and class_ not in node.attrs.get("class", "").split():
                continue
            out.append(node)
        return out

    def find(
        self,
        name: _Names = None,
        *,
        href: _Filter = False,
        style: _Filter = False,
        class_: str | None = None,
    ) -> Node | None:
        found = self.find_all(name, href=href, style=style, class_=class_)
        return found[0] if found else None

    def get_text(self, separator: str = "", strip: bool = False) -> str:
        """The text a reader sees.

        Script and style bodies are left out, because a reader never sees them.
        `separator` goes between runs and `strip` trims each run, which together
        match how the checks call BeautifulSoup today.
        """
        runs: list[str] = []
        for node in [self, *self.descendants()]:
            if node.tag is not None:
                continue
            if node.parent is not None and node.parent.tag == _COMMENT:
                continue
            if any(a.tag in _NON_VISIBLE for a in node.ancestors()):
                continue
            runs.append(node.text.strip() if strip else node.text)
        if strip:
            runs = [r for r in runs if r]
        return separator.join(runs)

    def ancestors(self) -> list[Node]:
        out, node = [], self.parent
        while node is not None:
            out.append(node)
            node = node.parent
        return out

    def append(self, text: str) -> None:
        """Add a run of text as the last child.

        One check marks block boundaries with a sentinel character before
        reading the text back, which is the only reason this exists.
        """
        self.children.append(Node(None, text=text, parent=self))

    def __call__(
        self,
        name: str | list[str] | bool | None = None,
        **kwargs: bool | str | None,
    ) -> list[Node]:
        """`node(...)` is `node.find_all(...)`, the shorthand the checks use."""
        return self.find_all(name, **kwargs)  # type: ignore[arg-type]

    def decode_contents(self) -> str:
        """This element's children, back as HTML.

        Only the forward stripper needs it, to hand the quoted original back to
        the content checks as markup rather than as text.
        """
        return "".join(child._as_markup() for child in self.children)

    def _as_markup(self) -> str:
        if self.tag == _COMMENT:
            return f"<!--{self.text}-->"
        if self.tag is None:
            return escape(self.text, quote=False)
        # Sorted, so the same element always serialises the same way.
        attrs = "".join(f' {k}="{escape(v, quote=True)}"' for k, v in sorted(self.attrs.items()))
        if self.tag in _VOID:
            # Self-closed, so the markup re-parses the same way anywhere.
            return f"<{self.tag}{attrs}/>"
        inner = "".join(c._as_markup() for c in self.children)
        return f"<{self.tag}{attrs}>{inner}</{self.tag}>"

    # ── editing ──────────────────────────────────────────────────────────

    def decompose(self) -> None:
        """Remove this element and everything inside it."""
        if self.parent is not None:
            self.parent.children = [c for c in self.parent.children if c is not self]
            self.parent = None

    extract = decompose

    # ── css ──────────────────────────────────────────────────────────────

    def select(self, selector: str) -> list[Node]:
        """Elements matching a simple CSS selector.

        Supports a tag, `.class`, `#id`, `[attr]`, and those joined by
        descendant spaces, which covers what an email's own style block uses to
        hide text. Anything richer raises ValueError, and the one caller already
        treats an unreadable selector as no match.
        """
        steps = [s for s in selector.strip().split() if s]
        if not steps:
            raise ValueError("empty selector")
        current = [self]
        for step in steps:
            # One element can be a descendant of several matched ancestors, so
            # collect by identity to keep it once, in document order.
            matched: list[Node] = []
            seen: set[int] = set()
            for node in current:
                for descendant in node.descendants():
                    if id(descendant) in seen or not _matches(descendant, step):
                        continue
                    seen.add(id(descendant))
                    matched.append(descendant)
            current = matched
        return current


_SIMPLE_RX = re.compile(r"^(?P<tag>[a-zA-Z][\w-]*|\*)?(?P<rest>(?:[.#][\w-]+|\[[\w-]+\])*)$")
_PART_RX = re.compile(r"[.#][\w-]+|\[[\w-]+\]")


def _matches(node: Node, step: str) -> bool:
    if node.tag is None or node.tag == _COMMENT:
        return False
    m = _SIMPLE_RX.match(step)
    if not m:
        raise ValueError(f"unsupported selector: {step!r}")
    tag = m.group("tag")
    if tag and tag != "*" and node.tag != tag.lower():
        return False
    for part in _PART_RX.findall(m.group("rest") or ""):
        if part.startswith("."):
            if part[1:] not in node.attrs.get("class", "").split():
                return False
        elif part.startswith("#"):
            if node.attrs.get("id") != part[1:]:
                return False
        elif not node.attrs.get(part[1:-1]):
            return False
    return True


class _TreeBuilder(HTMLParser):
    """Turns the parser's events into the tree above.

    `convert_charrefs` is on, so entities arrive already decoded in the text
    events and nothing here has to know about them.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = Node("[document]")
        self._open: list[Node] = [self.root]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        parent = self._open[-1]
        node = Node(tag, {k: (v if v is not None else "") for k, v in attrs}, parent=parent)
        parent.children.append(node)
        if tag not in _VOID:
            self._open.append(node)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        parent = self._open[-1]
        parent.children.append(
            Node(tag, {k: (v if v is not None else "") for k, v in attrs}, parent=parent)
        )

    def handle_endtag(self, tag: str) -> None:
        # Close back to the matching open tag. A template that never closed a
        # cell leaves tags open above it, and a stray closing tag matches
        # nothing, so both cases leave the stack where it was.
        for depth in range(len(self._open) - 1, 0, -1):
            if self._open[depth].tag == tag:
                del self._open[depth:]
                return

    def handle_comment(self, data: str) -> None:
        parent = self._open[-1]
        parent.children.append(Node(_COMMENT, text=data, parent=parent))

    def handle_data(self, data: str) -> None:
        parent = self._open[-1]
        parent.children.append(Node(None, text=data, parent=parent))

    def error(self, message: str) -> None:  # pragma: no cover - never raised
        """Required by the old HTMLParser interface. Bad markup is normal here."""


def parse_html(markup: str) -> Node:
    """Build a tree from an email's HTML. Never raises on bad markup."""
    builder = _TreeBuilder()
    builder.feed(markup or "")
    builder.close()
    return builder.root


__all__ = ["Node", "parse_html", "unescape"]
