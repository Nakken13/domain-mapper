"""TUI rendering: plain text without color, ANSI only when asked."""

from domain_mapper.tui import render


def test_menu_lists_numbered_options_and_back_key():
    text = render.render_menu("Main menu", ["Scope check", "Scan"], back="Quit")
    for expected in ("Main menu", "[1]", "Scope check", "[2]", "Scan", "[q]", "Quit"):
        assert expected in text
    assert "[0]" not in text


def test_menu_shows_info_key_when_requested():
    text = render.render_menu("Main menu", ["Scan"], info=True)
    assert "[0]" in text
    assert "Info" in text


def test_menu_without_color_has_no_ansi_escape():
    assert "\x1b" not in render.render_menu("Main menu", ["Scan"], color=False)


def test_menu_with_color_has_ansi_escape():
    assert "\x1b[" in render.render_menu("Main menu", ["Scan"], color=True)


def test_info_panel_contains_title_and_every_line():
    text = render.render_info("About", ("first line", "second line"))
    for expected in ("About", "first line", "second line"):
        assert expected in text


def test_prompt_is_plain_or_colored():
    plain = render.menu_prompt(color=False)
    assert plain.startswith("domain-mapper")
    assert "\x1b" not in plain
    assert "\x1b[" in render.menu_prompt(color=True)


def test_ascii_fallback_when_stdout_cannot_encode_box_drawing(monkeypatch):
    monkeypatch.setattr(render, "_unicode_printable", lambda: False)
    text = render.render_menu("Main menu", ["Scan"])
    assert "╭" not in text  # rounded corner
    assert "+" in text
    assert render.menu_prompt().startswith("domain-mapper >")
