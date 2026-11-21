"""Entry point `surfacemap-tool`: needs a terminal, exits cleanly on Ctrl-C."""

import pytest

from surfacemap import tui
from surfacemap.tui import flow


class _Tty:
    def isatty(self) -> bool:
        return True


def test_main_refuses_a_non_interactive_stdin(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", _NotTty())
    with pytest.raises(SystemExit) as stop:
        tui.main()
    assert stop.value.code == 2
    assert "interactive terminal" in capsys.readouterr().err


class _NotTty:
    def isatty(self) -> bool:
        return False


def test_main_shows_the_banner_then_runs_the_flow(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr("sys.stdin", _Tty())
    monkeypatch.setattr(flow, "show_banner", lambda _print: calls.append("banner"))
    monkeypatch.setattr(flow, "run", lambda: calls.append("run"))
    tui.main()
    assert calls == ["banner", "run"]


def test_enable_ansi_never_raises_even_without_a_console():
    tui._enable_ansi()


@pytest.mark.parametrize("interrupt", [KeyboardInterrupt, EOFError])
def test_main_exits_cleanly_on_ctrl_c_or_eof(monkeypatch, interrupt):
    def run() -> None:
        raise interrupt

    monkeypatch.setattr("sys.stdin", _Tty())
    monkeypatch.setattr(flow, "show_banner", lambda _print: None)
    monkeypatch.setattr(flow, "run", run)
    tui.main()  # no exception, no traceback
