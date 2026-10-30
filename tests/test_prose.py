"""`listed` renders values for a sentence, not as a Python container."""

from __future__ import annotations

from engine.prose import listed


def test_one_value_stands_alone() -> None:
    assert listed(["urgency"]) == "urgency"


def test_two_values_join_with_and() -> None:
    assert listed(["urgency", "money promises"]) == "urgency and money promises"


def test_three_or_more_take_commas_and_a_final_and() -> None:
    assert listed(["a", "b", "c"]) == "a, b and c"
    assert listed(["a", "b", "c", "d"]) == "a, b, c and d"


def test_nothing_in_the_output_looks_like_a_container() -> None:
    """The defect this exists for: a bracket or a quote in front of a sender."""
    rendered = listed(["list-unsubscribe", "list-unsubscribe-post"])
    assert rendered == "list-unsubscribe and list-unsubscribe-post"
    for ch in "[]{}'\"":
        assert ch not in rendered


def test_values_that_are_not_strings_are_rendered() -> None:
    assert listed([1, 2, 3]) == "1, 2 and 3"


def test_an_empty_input_gives_an_empty_string() -> None:
    """Documented, because a caller that reaches this has a bug above it."""
    assert listed([]) == ""


def test_a_generator_works() -> None:
    """Call sites pass comprehensions, so it cannot need a list."""
    assert listed(str(n) for n in (1, 2)) == "1 and 2"
