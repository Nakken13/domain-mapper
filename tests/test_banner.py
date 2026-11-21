"""Banner: braille art + title + version, centered on the terminal."""

import os

import pytest

from domain_mapper import __version__
from domain_mapper.banner import banner


@pytest.fixture
def terminal(monkeypatch):
    def _set(columns: int) -> None:
        monkeypatch.setattr(
            "domain_mapper.banner.shutil.get_terminal_size",
            lambda fallback=(80, 24): os.terminal_size((columns, 24)),
        )

    return _set


def test_banner_contains_title_and_version(terminal):
    terminal(120)
    text = banner()
    assert "|___/" in text  # last glyph row of the figlet title
    assert f"v{__version__}" in text


def test_banner_has_art_title_version_rows(terminal):
    terminal(120)
    lines = banner().splitlines()
    assert len(lines) >= 19 + 5 + 2  # art + title + blank/version lines
    assert any("⣿" in line for line in lines)


def test_banner_is_centered_and_fits_wide_terminal(terminal):
    terminal(120)
    lines = [line for line in banner().splitlines() if line.strip("⠀ ")]
    assert all(len(line) <= 120 for line in lines)
    version_line = next(line for line in lines if f"v{__version__}" in line)
    left = len(version_line) - len(version_line.lstrip())
    assert abs(left - (120 - len(version_line.strip())) // 2) <= 1


def test_banner_never_crashes_on_narrow_terminal(terminal):
    terminal(20)
    assert f"v{__version__}" in banner()  # centering degrades to no padding


def test_banner_skips_the_braille_art_when_the_terminal_is_too_narrow(terminal):
    terminal(40)
    text = banner()
    assert "⣿" not in text  # wrapped braille would be garbled
    assert f"v{__version__}" in text
