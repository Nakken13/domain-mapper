"""Interactive numbered-menu version of the CLI (same engine, same scope check)."""

import sys

_ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
_STD_OUTPUT_HANDLE = -11


def _enable_ansi() -> None:
    """Turns on ANSI escapes (screen clear, colors) in the Windows console; no-op elsewhere."""
    if sys.platform != "win32":
        return
    import ctypes

    kernel32 = ctypes.windll.kernel32
    handle = kernel32.GetStdHandle(_STD_OUTPUT_HANDLE)
    mode = ctypes.c_ulong()
    if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):  # 0 when stdout is not a console
        kernel32.SetConsoleMode(handle, mode.value | _ENABLE_VIRTUAL_TERMINAL_PROCESSING)


def main() -> None:
    """Entry point of `domain-mapper-tool`."""
    if not sys.stdin.isatty():
        print(
            "Error: the menu needs an interactive terminal; use `domain-mapper <command>`.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    from domain_mapper.tui import flow  # late import: flow imports the CLI (heavy), not needed above

    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        reconfigure(errors="replace")  # braille outside the console encoding: no crash
    _enable_ansi()
    flow.show_banner(print)
    try:
        flow.run()
    except (KeyboardInterrupt, EOFError):
        print()  # Ctrl-C / Ctrl-D: leave on a fresh line, no traceback
