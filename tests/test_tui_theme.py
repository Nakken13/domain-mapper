"""Neptune-night palette: hex colors, gradients, truecolor with a 256-color fallback."""

import re

import pytest

from domain_mapper.tui import theme

ANSI = re.compile(r"\x1b\[[0-9;]*m")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ("NO_COLOR", "COLORTERM", "WT_SESSION"):
        monkeypatch.delenv(name, raising=False)


def test_palette_is_blue_violet_hex():
    for color in (theme.NEPTUNE, theme.VIOLET, theme.LAVENDER, theme.MUTED, theme.NIGHT):
        assert re.fullmatch(r"#[0-9a-f]{6}", color)


def test_truecolor_escape_when_the_terminal_supports_it(monkeypatch):
    monkeypatch.setenv("COLORTERM", "truecolor")
    assert theme.fg("#102030") == "\x1b[38;2;16;32;48m"


def test_256_color_fallback_when_truecolor_is_unknown(monkeypatch):
    monkeypatch.setattr(theme, "supports_truecolor", lambda: False)
    escape = theme.fg("#a78bfa")
    assert re.fullmatch(r"\x1b\[38;5;\d{1,3}m", escape)


def test_paint_wraps_text_and_resets():
    painted = theme.paint("hi", theme.VIOLET, bold=True)
    assert painted.endswith("\x1b[0m")
    assert "hi" in painted
    assert ANSI.sub("", painted) == "hi"


def test_gradient_keeps_the_visible_text_and_changes_color_along_it():
    painted = theme.gradient("abcdef", theme.NEPTUNE, theme.VIOLET)
    assert ANSI.sub("", painted) == "abcdef"
    escapes = ANSI.findall(painted)
    assert len(set(escapes)) > 2  # not a flat color


def test_gradient_leaves_spaces_unpainted_and_handles_empty_text():
    assert theme.gradient("", theme.NEPTUNE, theme.VIOLET) == ""
    painted = theme.gradient("a b", theme.NEPTUNE, theme.VIOLET)
    assert ANSI.sub("", painted) == "a b"


def test_no_color_env_disables_every_escape(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert not theme.color_enabled(True)
    assert theme.paint("hi", theme.VIOLET) == "hi"
    assert theme.gradient("hi", theme.NEPTUNE, theme.VIOLET) == "hi"


def test_vertical_gradient_colors_each_line_differently():
    lines = theme.vertical_gradient(["aaa", "bbb", "ccc"], theme.NEPTUNE, theme.VIOLET)
    assert [ANSI.sub("", line) for line in lines] == ["aaa", "bbb", "ccc"]
    assert len({ANSI.findall(line)[0] for line in lines}) == 3
