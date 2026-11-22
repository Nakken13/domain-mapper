"""Menu flow: scan a domain, open the last report. Delegates to the CLI `scan` command.

The default command calls `cli.scan` itself, so the menu has no second code path: the domain is
validated first, exactly as with `domain-mapper scan`.
"""

import sys
import webbrowser
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

import typer

from domain_mapper import cli
from domain_mapper.banner import banner
from domain_mapper.tui.prompts import InputFn, PrintFn, ask, choose
from domain_mapper.tui.render import render_info

OpenFn = Callable[[str], object]
ScanFn = Callable[[str, Path | None], int]

_CLEAR_SCREEN = "\x1b[2J\x1b[3J\x1b[H"
_ACTIONS = ("Scan a domain", "Open the last report")
_ABOUT = (
    "domain-mapper maps the attack surface of a domain from public sources only (passive).",
    "Nothing is sent to the target itself: DNS, certificate logs and other public databases.",
    "Only use it on domains you own or are authorized to assess.",
)


def _exit_code(command: Callable[..., None], *args: object) -> int:
    """Runs a CLI command; the `typer.Exit` it raises becomes its exit code.

    Any other failure (network, disk, plugin bug) is reported and returns 2 instead of killing the
    menu; Ctrl-C is not an `Exception`, so it still propagates."""
    try:
        command(*args)
    except typer.Exit as stop:
        return stop.exit_code
    except Exception as exc:
        typer.secho(f"ERROR {type(exc).__name__}: {exc}", fg=typer.colors.RED, err=True)
        return 2
    return 0


def default_scan(domain: str, output: Path | None) -> int:
    return _exit_code(cli.scan, domain, output)


def show_banner(print_fn: PrintFn) -> None:
    print_fn(_CLEAR_SCREEN + "\n" + banner().rstrip("\n"))


def _hostname(typed: str) -> str:
    """Hostname of a pasted URL (`https://host:8443/a?b` -> `host`); other input unchanged.

    Typing convenience only: the strict validation still runs on the result,
    so garbage is refused exactly as before."""
    text = typed.strip()
    try:
        host = urlsplit(text if "://" in text else f"//{text}").hostname
    except ValueError:
        return typed
    return host or typed


def _scan(input_fn: InputFn, print_fn: PrintFn, scan_fn: ScanFn) -> Path | None:
    """Asks domain and output, runs the scan; returns the report path if it was written."""
    domain = _hostname(ask("Domain to scan", optional=False, input_fn=input_fn, print_fn=print_fn))
    default = f"{domain}-report.html"
    answer = ask(f"Report file, default {default}", input_fn=input_fn, print_fn=print_fn)
    target = Path(answer or default)
    return target if scan_fn(domain, target) == 0 else None


def _open_report(last_report: Path | None, print_fn: PrintFn, open_fn: OpenFn) -> None:
    if last_report is None:
        print_fn("No report yet: run a scan first.")
    elif not last_report.is_file():
        print_fn(f"Report not found: {last_report}")
    else:
        if open_fn(last_report.resolve().as_uri()):
            print_fn(f"Opened {last_report} in the browser.")
        else:
            print_fn(f"Could not open a browser: open {last_report.resolve()} by hand.")


def run(
    input_fn: InputFn = input,
    print_fn: PrintFn = print,
    open_fn: OpenFn = webbrowser.open,
    *,
    scan_fn: ScanFn = default_scan,
) -> None:
    """Main loop; returns when the user quits (`q`)."""
    last_report: Path | None = None

    def show_about() -> None:
        print_fn("\n" + render_info("About domain-mapper", _ABOUT, color=sys.stdout.isatty()))

    while (
        index := choose(
            "domain-mapper",
            _ACTIONS,
            back="Quit",
            on_info=show_about,
            input_fn=input_fn,
            print_fn=print_fn,
        )
    ) is not None:
        if index == 0:
            written = _scan(input_fn, print_fn, scan_fn)
            last_report = written or last_report
        else:
            _open_report(last_report, print_fn, open_fn)
