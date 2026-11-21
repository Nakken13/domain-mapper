"""Rich rendering of the menus: strings only, no I/O (the caller prints)."""

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

_PANEL_WIDTH = 64


def _unicode_printable() -> bool:
    """False when stdout's encoding cannot show box drawing (e.g. cp1252): ASCII fallback."""
    try:
        "\u256d\u276f".encode(sys.stdout.encoding or "ascii")
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def _print_centered(panel: Panel, *, color: bool) -> str:
    terminal = shutil.get_terminal_size((80, 24)).columns
    buffer = StringIO()
    console = Console(
        file=buffer, width=terminal, force_terminal=color, color_system="256" if color else None
    )
    console.print(Align.center(panel))
    return "\n".join(line.rstrip() for line in buffer.getvalue().splitlines())


def _panel(body: Group | Table, title: str) -> Panel:
    terminal = shutil.get_terminal_size((80, 24)).columns
    return Panel(
        body,
        title=Text(title, style="bold"),
        title_align="left",
        box=box.ROUNDED if _unicode_printable() else box.ASCII,
        border_style="cyan",
        padding=(0, 2),
        width=min(terminal, _PANEL_WIDTH),
    )


def render_menu(
    title: str,
    options: Sequence[str],
    *,
    back: str = "Back",
    info: bool = False,
    color: bool = False,
) -> str:
    """Numbered menu in a panel; the info and back keys sit below a rule."""
    rows = Table.grid(padding=(0, 2))
    rows.add_column(justify="right")
    rows.add_column(no_wrap=True)
    for number, option in enumerate(options, start=1):
        rows.add_row(Text(f"[{number}]", style="bold cyan"), Text(option, style="bold"))
    keys = Text()
    if info:
        keys.append("[0]", style="bold cyan").append("  Info", style="dim").append("        ")
    keys.append("[q]", style="bold color(208)").append(f"  {back}", style="dim")
    rule = Rule(style="dim", characters="─" if _unicode_printable() else "-")
    return _print_centered(_panel(Group(rows, rule, Align.center(keys)), title), color=color)


def render_info(title: str, lines: Sequence[str], *, color: bool = False) -> str:
    """Panel (same width as the menu) with one wrapped paragraph per line."""
    return _print_centered(_panel(Group(*(Text(line) for line in lines)), title), color=color)


def menu_prompt(*, color: bool = False) -> str:
    """Input prompt: `surfacemap` + arrow (bold white when `color`), ASCII `>` if needed."""
    arrow = chr(0x276F) if _unicode_printable() else ">"  # heavy right-pointing angle quotation
    text = f"surfacemap {arrow}"
    return f"\x1b[1;97m{text}\x1b[0m " if color else f"{text} "
