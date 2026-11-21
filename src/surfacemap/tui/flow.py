"""Menu flow: scope check, scan, open the last report. Delegates to the CLI commands.

The default commands call `cli.scope_check` / `cli.scan` themselves, so the menu has no second
code path: the scope is checked first, exactly as with `surfacemap scan`.
"""

import sys
import webbrowser
from collections.abc import Callable
from pathlib import Path

import typer

from surfacemap import cli
from surfacemap.banner import banner
from surfacemap.tui.prompts import InputFn, PrintFn, ask, choose
from surfacemap.tui.render import render_info

OpenFn = Callable[[str], object]
ScopeCheckFn = Callable[[str, Path], int]
ScanFn = Callable[[str, Path, Path | None], int]

_CLEAR_SCREEN = "\x1b[2J\x1b[3J\x1b[H"
_ACTIONS = ("Scope check", "Scan a domain", "Open the last report")
_ABOUT = (
    "SurfaceMap maps the attack surface of a domain from public sources only (passive).",
    "A domain is refused unless it is listed in your scope file: the check runs first and",
    "nothing is queried for a refused domain.",
    "Only use it on domains you own or are authorized to assess.",
)


def _exit_code(command: Callable[..., None], *args: object) -> int:
    """Runs a CLI command; the `typer.Exit` it raises becomes its exit code."""
    try:
        command(*args)
    except typer.Exit as stop:
        return stop.exit_code
    return 0


def default_scope_check(domain: str, scope_file: Path) -> int:
    return _exit_code(cli.scope_check, domain, scope_file)


def default_scan(domain: str, scope_file: Path, output: Path | None) -> int:
    return _exit_code(cli.scan, domain, scope_file, output)


def show_banner(print_fn: PrintFn) -> None:
    print_fn(_CLEAR_SCREEN + "\n" + banner().rstrip("\n"))


def _scan(scope_file: Path, input_fn: InputFn, print_fn: PrintFn, scan_fn: ScanFn) -> Path | None:
    """Asks domain and output, runs the scan; returns the report path if it was written."""
    domain = ask("Domain to scan", optional=False, input_fn=input_fn, print_fn=print_fn)
    default = f"{domain}-report.html"
    answer = ask(f"Report file, default {default}", input_fn=input_fn, print_fn=print_fn)
    target = Path(answer or default)
    return target if scan_fn(domain, scope_file, target) == 0 else None


def _open_report(last_report: Path | None, print_fn: PrintFn, open_fn: OpenFn) -> None:
    if last_report is None:
        print_fn("No report yet: run a scan first.")
    elif not last_report.is_file():
        print_fn(f"Report not found: {last_report}")
    else:
        open_fn(last_report.resolve().as_uri())
        print_fn(f"Opened {last_report} in the browser.")


def run(
    input_fn: InputFn = input,
    print_fn: PrintFn = print,
    open_fn: OpenFn = webbrowser.open,
    *,
    scope_file: Path = Path("scope.yaml"),
    scope_check_fn: ScopeCheckFn = default_scope_check,
    scan_fn: ScanFn = default_scan,
) -> None:
    """Main loop; returns when the user quits (`q`)."""
    last_report: Path | None = None

    def show_about() -> None:
        print_fn("\n" + render_info("About SurfaceMap", _ABOUT, color=sys.stdout.isatty()))

    while (
        index := choose(
            "SurfaceMap",
            _ACTIONS,
            back="Quit",
            on_info=show_about,
            input_fn=input_fn,
            print_fn=print_fn,
        )
    ) is not None:
        if index == 0:
            domain = ask("Domain to check", optional=False, input_fn=input_fn, print_fn=print_fn)
            scope_check_fn(domain, scope_file)
        elif index == 1:
            written = _scan(scope_file, input_fn, print_fn, scan_fn)
            last_report = written or last_report
        else:
            _open_report(last_report, print_fn, open_fn)
