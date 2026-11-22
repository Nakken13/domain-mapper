"""TUI rendering: plain text without color, ANSI only when asked."""

import os

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


def test_menu_shows_a_hint_under_each_option():
    text = render.render_menu(
        "Main menu", ["Scan a domain", "Open"], hints=["map it", "see it"], back="Quit"
    )
    assert "map it" in text
    assert "see it" in text


def test_menu_uses_the_neptune_palette_when_colored(monkeypatch):
    monkeypatch.setenv("COLORTERM", "truecolor")
    monkeypatch.delenv("NO_COLOR", raising=False)
    text = render.render_menu("Main menu", ["Scan"], color=True)
    assert "38;2;79;140;255" in text  # NEPTUNE border
    assert "38;2;167;123;255" in text  # VIOLET accent
    assert "36m" not in text  # the old stock cyan is gone
    assert "38;5;208" not in text  # and the old orange quit key


def test_menu_stays_plain_with_no_color_even_on_a_terminal(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert "\x1b" not in render.render_menu("Main menu", ["Scan"], color=True)
    assert "\x1b" not in render.menu_prompt(color=True)


def test_field_prompt_is_plain_or_colored():
    assert render.field_prompt("Domain to scan", color=False) == "Domain to scan : "
    colored = render.field_prompt("Domain to scan", color=True)
    assert "\x1b[" in colored
    assert "Domain to scan" in colored


def test_menu_is_not_wider_than_a_small_terminal(monkeypatch):
    monkeypatch.setattr(
        render.shutil, "get_terminal_size", lambda fallback=(80, 24): os.terminal_size((50, 24))
    )
    text = render.render_menu("Main menu", ["Scan"], hints=["a long hint " * 5])
    assert max(len(line) for line in text.splitlines()) <= 50
