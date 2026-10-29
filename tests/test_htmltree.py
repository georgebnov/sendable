"""The HTML tree the content checks read.

Every expectation here was taken from BeautifulSoup's answer for the same
markup, before it was removed, so this file is the record of that behaviour
rather than a fresh opinion about it.

Email HTML is bad HTML, so most of these are shapes a real template ships:
unclosed cells, stray closing tags, Outlook conditional comments, text hidden
in a styled element.
"""

from __future__ import annotations

import pytest

from engine.htmltree import parse_html

# ── text a reader sees ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("name", "markup", "expected"),
    [
        ("plain", "<p>Hello there</p>", "Hello there"),
        ("unclosed cells", "<table><tr><td>one<td>two</table><p>after", "one two after"),
        ("stray close tag", "<div>text</span></div>", "text"),
        ("nested unclosed p", "<p>a<p>b<p>c</p>", "a b c"),
        ("entities decoded", "<p>caf&eacute; &amp; more</p>", "café & more"),
        ("uppercase tags", "<P>Upper</P>", "Upper"),
        ("deeply nested", "<div><div><p><b>deep</b> text</p></div></div>", "deep text"),
    ],
)
def test_visible_text(name: str, markup: str, expected: str) -> None:
    assert parse_html(markup).get_text(" ", strip=True) == expected


@pytest.mark.parametrize(
    ("name", "markup"),
    [
        ("script body", "<script>var secret = 1</script><p>body</p>"),
        ("style body", "<style>p{color:red}</style><p>body</p>"),
        ("conditional comment", "<!--[if mso]>hidden markup<![endif]--><p>body</p>"),
    ],
)
def test_text_a_reader_never_sees_is_left_out(name: str, markup: str) -> None:
    assert parse_html(markup).get_text(" ", strip=True) == "body"


# ── finding elements ─────────────────────────────────────────────────────


def test_links_and_their_destinations() -> None:
    tree = parse_html("<a href='u'><img src='s'></a><br><a>no href</a><a href='v'>t</a>")
    assert [a.get("href") for a in tree.find_all("a", href=True)] == ["u", "v"]


def test_find_all_takes_one_tag_a_list_or_everything() -> None:
    tree = parse_html("<div><p>a</p><span>b</span><img src='s'></div>")
    assert len(tree.find_all("p")) == 1
    assert len(tree.find_all(["p", "span"])) == 2
    assert [n.name for n in tree.find_all(True)] == ["div", "p", "span", "img"]


def test_find_returns_the_first_or_nothing() -> None:
    tree = parse_html("<div class='a'>one</div><div class='a'>two</div>")
    first = tree.find("div", class_="a")
    assert first is not None
    assert first.get_text(strip=True) == "one"
    assert tree.find("section") is None


def test_filtering_by_attribute() -> None:
    tree = parse_html("<p style='display:none'>x</p><p>y</p>")
    assert len(tree.find_all(style=True)) == 1


def test_a_void_element_never_swallows_what_follows() -> None:
    """An unclosed img used to eat the rest of the message."""
    tree = parse_html("<p>before<img src='s'>after</p><p>next</p>")
    assert tree.get_text(" ", strip=True) == "before after next"


# ── css selectors ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("selector", "expected"),
    [
        ("p", ["p"]),
        (".b", ["p"]),
        ("#hero", ["div"]),
        ("div p", ["p"]),
        ("[style]", ["p"]),
        ("*", ["div", "p"]),
    ],
)
def test_select(selector: str, expected: list[str]) -> None:
    tree = parse_html("<div id='hero' class='a'><p class='b' style='x'>t</p></div>")
    assert [n.name for n in tree.select(selector)] == expected


def test_a_descendant_is_returned_once_however_many_ancestors_match() -> None:
    tree = parse_html("<div><div><div><p>deep</p></div></div></div>")
    assert [n.name for n in tree.select("div p")] == ["p"]


def test_a_selector_it_cannot_read_says_so() -> None:
    """The caller treats this as no match, which is why it must raise."""
    with pytest.raises(ValueError):
        parse_html("<p>x</p>").select("p:nth-child(2n+1)")


# ── editing and round-tripping ───────────────────────────────────────────


def test_decompose_removes_the_element_and_its_contents() -> None:
    tree = parse_html("<div><p class='drop'>gone</p><p>kept</p></div>")
    drop = tree.find("p", class_="drop")
    assert drop is not None
    drop.decompose()
    assert tree.get_text(" ", strip=True) == "kept"


def test_append_adds_text_at_the_end() -> None:
    tree = parse_html("<p>body</p>")
    para = tree.find("p")
    assert para is not None
    para.append("|MARK|")
    assert tree.get_text("", strip=False) == "body|MARK|"


def test_markup_round_trips_with_sorted_attributes() -> None:
    tree = parse_html("<a href='u'><img src='s' alt='a'></a>")
    assert tree.decode_contents() == '<a href="u"><img alt="a" src="s"/></a>'


def test_a_comment_keeps_its_place_in_the_markup() -> None:
    tree = parse_html("<!--[if mso]><td><![endif]--><p>hi</p>")
    assert tree.decode_contents() == "<!--[if mso]><td><![endif]--><p>hi</p>"


def test_the_callable_form_is_find_all() -> None:
    tree = parse_html("<script>a</script><style>b</style><p>c</p>")
    assert len(tree(["script", "style"])) == 2


def test_nothing_in_an_email_makes_it_raise() -> None:
    """A parser that raises on bad markup is useless here."""
    for markup in ("", "<", "<<>>", "<p", "</p>", "<p>" * 200, "<!--unclosed"):
        parse_html(markup).get_text(" ", strip=True)
