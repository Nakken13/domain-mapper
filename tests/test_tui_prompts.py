"""Prompts: the only TUI module that reads input; I/O is injected."""

from collections.abc import Iterator

from surfacemap.tui import prompts


def _inputs(*answers: str) -> prompts.InputFn:
    feed: Iterator[str] = iter(answers)
    return lambda _prompt: next(feed)


def _printer() -> tuple[list[str], prompts.PrintFn]:
    out: list[str] = []
    return out, out.append


def test_choose_returns_zero_based_index():
    _, print_fn = _printer()
    assert prompts.choose("T", ["a", "b", "c"], input_fn=_inputs("2"), print_fn=print_fn) == 1


def test_choose_q_means_back():
    _, print_fn = _printer()
    assert prompts.choose("T", ["a"], input_fn=_inputs("q"), print_fn=print_fn) is None
    assert prompts.choose("T", ["a"], input_fn=_inputs("Q"), print_fn=print_fn) is None


def test_choose_asks_again_on_invalid_entry():
    out, print_fn = _printer()
    index = prompts.choose(
        "T", ["a", "b"], input_fn=_inputs("", "x", "0", "3", "1"), print_fn=print_fn
    )
    assert index == 0
    assert sum("Invalid choice" in line for line in out) == 4


def test_choose_zero_runs_info_then_shows_menu_again():
    out, print_fn = _printer()
    calls: list[str] = []
    index = prompts.choose(
        "T",
        ["a"],
        on_info=lambda: calls.append("info"),
        input_fn=_inputs("0", "1"),
        print_fn=print_fn,
    )
    assert index == 0
    assert calls == ["info"]
    assert len(out) == 2  # menu printed before and after the info


def test_ask_returns_stripped_value():
    _, print_fn = _printer()
    assert prompts.ask("Domain", input_fn=_inputs("  example.com "), print_fn=print_fn) == (
        "example.com"
    )


def test_ask_required_repeats_until_a_value_is_given():
    out, print_fn = _printer()
    value = prompts.ask(
        "Domain", optional=False, input_fn=_inputs("", "  ", "x"), print_fn=print_fn
    )
    assert value == "x"
    assert out.count("A value is required.") == 2


def test_ask_optional_returns_empty_on_enter():
    _, print_fn = _printer()
    assert prompts.ask("Output", input_fn=_inputs(""), print_fn=print_fn) == ""
