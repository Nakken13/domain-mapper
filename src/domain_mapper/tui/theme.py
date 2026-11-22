"""Neptune-night palette (deep blue to violet) and the few ANSI helpers built on it.

Strings only, no I/O. Truecolor when the terminal can (Windows Terminal, VS Code, most modern
emulators), nearest 256-color otherwise; `NO_COLOR` turns every escape off.
"""

import os
import sys
from collections.abc import Sequence

NIGHT = "#0c0e2b"  # deep midnight: text on a bright chip
NEPTUNE = "#4f8cff"  # Neptune blue: borders, first end of every gradient
INDIGO = "#6c63f0"
VIOLET = "#a77bff"  # accents, second end of every gradient
LAVENDER = "#dcd3ff"  # main text
MUTED = "#7f87bd"  # hints, rules, secondary text

_RESET = "\x1b[0m"
_BOLD = "\x1b[1m"


def color_enabled(requested: bool) -> bool:
    """`requested` (stdout is a terminal) unless the user opted out with NO_COLOR."""
    return requested and "NO_COLOR" not in os.environ


def supports_truecolor() -> bool:
    env = os.environ
    return (
        env.get("COLORTERM", "").lower() in {"truecolor", "24bit"}
        or "WT_SESSION" in env  # Windows Terminal
        or sys.platform == "win32"  # conhost 1703+ understands 24-bit once VT is enabled
    )


def rich_color_system() -> str:
    """Color system to hand to `rich.Console`: it downgrades hex styles on its own."""
    return "truecolor" if supports_truecolor() else "256"


def _rgb(hex_color: str) -> tuple[int, int, int]:
    value = hex_color.lstrip("#")
    return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)


def _to_256(red: int, green: int, blue: int) -> int:
    """Nearest color in the 6x6x6 cube of the xterm 256 palette."""
    r, g, b = (round(channel / 255 * 5) for channel in (red, green, blue))
    return 16 + 36 * r + 6 * g + b


def fg(hex_color: str) -> str:
    red, green, blue = _rgb(hex_color)
    if supports_truecolor():
        return f"\x1b[38;2;{red};{green};{blue}m"
    return f"\x1b[38;5;{_to_256(red, green, blue)}m"


def paint(text: str, hex_color: str, *, bold: bool = False, enabled: bool = True) -> str:
    """`text` in `hex_color`; unchanged when color is off."""
    if not enabled or "NO_COLOR" in os.environ:
        return text
    weight = _BOLD if bold else ""
    return f"{weight}{fg(hex_color)}{text}{_RESET}"


def _mix(start: str, end: str, ratio: float) -> str:
    a, b = _rgb(start), _rgb(end)
    red, green, blue = (round(x + (y - x) * ratio) for x, y in zip(a, b, strict=True))
    return f"#{red:02x}{green:02x}{blue:02x}"


def gradient(text: str, start: str, end: str, *, enabled: bool = True) -> str:
    """Horizontal gradient, one escape per visible character (spaces stay unpainted)."""
    if not text or not enabled or "NO_COLOR" in os.environ:
        return text
    last = max(len(text) - 1, 1)
    out: list[str] = []
    for index, char in enumerate(text):
        out.append(char if char.isspace() else f"{fg(_mix(start, end, index / last))}{char}")
    return "".join(out) + _RESET


def vertical_gradient(
    lines: Sequence[str], start: str, end: str, *, enabled: bool = True
) -> list[str]:
    """One flat color per line, blending from `start` (first line) to `end` (last)."""
    if not enabled or "NO_COLOR" in os.environ:
        return list(lines)
    last = max(len(lines) - 1, 1)
    return [
        f"{fg(_mix(start, end, index / last))}{line}{_RESET}" if line.strip() else line
        for index, line in enumerate(lines)
    ]
