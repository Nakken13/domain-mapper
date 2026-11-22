"""Rich rendering of the menus: strings only, no I/O (the caller prints).

Look: a double-line "observatory" frame in Neptune blue, violet key caps, lavender text, muted
hints (see `theme.py`). Everything degrades: ASCII frame when the console cannot print box
drawing, no escape at all without a terminal or with `NO_COLOR`."""

import shutil
import sys
from collections.abc import Sequence
from io import StringIO

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from domain_mapper.tui import theme

_PANEL_WIDTH = 66


def _unicode_printable() -> bool:
    """False when stdout's encoding cannot show box drawing (e.g. cp1252): ASCII fallback."""
    try:
        "\u2554\u276f\u25c8\u2501".encode(sys.stdout.encoding or "ascii")
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def _print_centered(panel: Panel, *, color: bool) -> str:
    terminal = shutil.get_terminal_size((80, 24)).columns
    buffer = StringIO()
    console = Console(
        file=buffer,
        width=terminal,
        force_terminal=color,
        color_system=theme.rich_color_system() if color else None,
    )
    console.print(Align.center(panel))
    return "\n".join(line.rstrip() for line in buffer.getvalue().splitlines())


def _panel(body: Group | Table, title: str) -> Panel:
    terminal = shutil.get_terminal_size((80, 24)).columns
    fancy = _unicode_printable()
    return Panel(
        body,
        title=Text(f"{'◈' if fancy else '*'} {title}", style=f"bold {theme.VIOLET}"),
        title_align="left",
        box=box.DOUBLE if fancy else box.ASCII,
        border_style=theme.NEPTUNE,
        padding=(0, 2),
        width=min(terminal, _PANEL_WIDTH),
    )


def render_menu(
    title: str,
    options: Sequence[str],
    *,
    hints: Sequence[str] = (),
    back: str = "Back",
    info: bool = False,
    color: bool = False,
) -> str:
    """Numbered menu in a framed panel; the info and back keys sit below a rule.

    `hints` (optional, one per option) is a short muted line shown beside each option."""
    color = theme.color_enabled(color)
    rows = Table.grid(padding=(0, 2))
    rows.add_column(justify="right", no_wrap=True)
    rows.add_column(no_wrap=True)
    rows.add_column(overflow="fold")
    for number, option in enumerate(options, start=1):
        hint = hints[number - 1] if number <= len(hints) else ""
        rows.add_row(
            Text(f"[{number}]", style=f"bold {theme.VIOLET}"),
            Text(option, style=f"bold {theme.LAVENDER}"),
            Text(hint, style=theme.MUTED),
        )
    keys = Text()
    if info:
        keys.append("[0]", style=f"bold {theme.NEPTUNE}").append("  Info", style=theme.MUTED)
        keys.append("        ")
    keys.append("[q]", style=f"bold {theme.NEPTUNE}").append(f"  {back}", style=theme.MUTED)
    rule = Rule(style=theme.MUTED, characters="━" if _unicode_printable() else "-")
    return _print_centered(_panel(Group(rows, rule, Align.center(keys)), title), color=color)


def render_info(title: str, lines: Sequence[str], *, color: bool = False) -> str:
    """Panel (same width as the menu) with one wrapped paragraph per line."""
    color = theme.color_enabled(color)
    body = Group(*(Text(line, style=theme.LAVENDER) for line in lines))
    return _print_centered(_panel(body, title), color=color)


def _arrow() -> str:
    return chr(0x276F) if _unicode_printable() else ">"  # heavy right-pointing angle quotation


def menu_prompt(*, color: bool = False) -> str:
    """Input prompt: `domain-mapper` + arrow (lavender and violet when `color`), ASCII `>`."""
    color = theme.color_enabled(color)
    name = theme.paint("domain-mapper", theme.LAVENDER, bold=True, enabled=color)
    return f"{name} {theme.paint(_arrow(), theme.VIOLET, bold=True, enabled=color)} "


def field_prompt(label: str, *, skip: bool = False, color: bool = False) -> str:
    """Prompt of a free-text field: `Domain to scan : ` (`skip` adds the ENTER hint)."""
    color = theme.color_enabled(color)
    head = theme.paint(label, theme.LAVENDER, bold=True, enabled=color)
    hint = theme.paint(" (ENTER to skip)", theme.MUTED, enabled=color) if skip else ""
    return f"{head}{hint} {theme.paint(':', theme.VIOLET, bold=True, enabled=color)} "
