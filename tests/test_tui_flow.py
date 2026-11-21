"""Menu flow: scripted inputs, fake commands, no network."""

from collections.abc import Iterator
from pathlib import Path

import pytest

from domain_mapper.tui import flow

SCOPE = Path("scope.yaml")


class Session:
    """Drives `flow.run` with scripted answers and records every side effect."""

    def __init__(self, *answers: str, scan_code: int = 0, check_code: int = 0) -> None:
        self._feed: Iterator[str] = iter(answers)
        self.out: list[str] = []
        self.checks: list[tuple[str, Path]] = []
        self.scans: list[tuple[str, Path, Path | None]] = []
        self.opened: list[str] = []
        self._scan_code = scan_code
        self._check_code = check_code

    def _check(self, domain: str, scope_file: Path) -> int:
        self.checks.append((domain, scope_file))
        return self._check_code

    def _scan(self, domain: str, scope_file: Path, output: Path | None) -> int:
        self.scans.append((domain, scope_file, output))
        return self._scan_code

    def _open(self, uri: str) -> bool:
        self.opened.append(uri)
        return True

    def run(self) -> str:
        flow.run(
            input_fn=lambda _prompt: next(self._feed),
            print_fn=self.out.append,
            open_fn=self._open,
            scope_file=SCOPE,
            scope_check_fn=self._check,
            scan_fn=self._scan,
        )
        return "\n".join(self.out)


def test_quit_immediately():
    session = Session("q")
    session.run()
    assert session.checks == []
    assert session.scans == []


def test_scope_check_passes_domain_and_scope_file():
    session = Session("1", "example.com", "q")
    session.run()
    assert session.checks == [("example.com", SCOPE)]
    assert session.scans == []


def test_scan_uses_default_report_name_when_output_left_empty():
    session = Session("2", "example.com", "", "q")
    session.run()
    assert session.scans == [("example.com", SCOPE, Path("example.com-report.html"))]


def test_scan_uses_the_chosen_output_path():
    session = Session("2", "example.com", "out.html", "q")
    session.run()
    assert session.scans == [("example.com", SCOPE, Path("out.html"))]


def test_open_last_report_after_a_successful_scan(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    report = tmp_path / "r.html"
    report.write_text("<html></html>", encoding="utf-8")
    session = Session("2", "example.com", str(report), "3", "q")
    session.run()
    assert session.opened == [report.resolve().as_uri()]


def test_open_report_without_scan_explains_and_opens_nothing():
    session = Session("3", "q")
    text = session.run()
    assert session.opened == []
    assert "No report yet" in text


def test_refused_scan_is_not_remembered_as_a_report():
    session = Session("2", "evil.test", "", "3", "q", scan_code=1)
    text = session.run()
    assert session.opened == []
    assert "No report yet" in text


def test_open_report_missing_on_disk_does_not_open(tmp_path: Path):
    gone = tmp_path / "gone.html"
    session = Session("2", "example.com", str(gone), "3", "q")
    text = session.run()
    assert session.opened == []
    assert "not found" in text


def test_info_entry_shows_the_passive_guarantee():
    session = Session("0", "q")
    text = session.run()
    assert "passive" in text.lower()
    assert "scope" in text.lower()


# --- the default commands go through the real CLI: scope first, nothing bypassed ---------------


@pytest.fixture
def scope_file(tmp_path: Path) -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text(
        "authorized:\n  - domain: example.com\n    authorization: owner\n", encoding="utf-8"
    )
    return path


def test_default_scope_check_returns_cli_exit_codes(scope_file: Path):
    assert flow.default_scope_check("example.com", scope_file) == 0
    assert flow.default_scope_check("other.test", scope_file) == 1


def test_default_scan_refuses_out_of_scope_before_any_collection(
    scope_file: Path, tmp_path: Path, monkeypatch
):
    def boom(*_args, **_kwargs):
        raise AssertionError("collection must not start for an out-of-scope domain")

    monkeypatch.setattr("domain_mapper.cli._collect", boom)
    code = flow.default_scan("other.test", scope_file, tmp_path / "r.html")
    assert code == 1
    assert not (tmp_path / "r.html").exists()


def test_default_scan_reports_a_missing_scope_file(tmp_path: Path):
    assert flow.default_scan("example.com", tmp_path / "nope.yaml", None) == 2


def test_default_scan_survives_an_unexpected_error(scope_file: Path, monkeypatch, capsys):
    def explode(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("domain_mapper.cli.scan", explode)
    assert flow.default_scan("example.com", scope_file, None) == 2
    assert "disk full" in capsys.readouterr().err


def test_open_report_warns_when_no_browser_could_open_it(tmp_path: Path):
    report = tmp_path / "r.html"
    report.write_text("<html></html>", encoding="utf-8")
    out: list[str] = []
    flow._open_report(report, out.append, lambda _uri: False)
    assert any("Could not open" in line for line in out)
