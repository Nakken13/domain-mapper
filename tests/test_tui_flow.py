"""Menu flow: scripted inputs, fake commands, no network."""

from collections.abc import Iterator
from pathlib import Path

import pytest

from domain_mapper.tui import flow


class Session:
    """Drives `flow.run` with scripted answers and records every side effect."""

    def __init__(self, *answers: str, scan_code: int = 0) -> None:
        self._feed: Iterator[str] = iter(answers)
        self.out: list[str] = []
        self.scans: list[tuple[str, Path | None]] = []
        self.opened: list[str] = []
        self._scan_code = scan_code

    def _scan(self, domain: str, output: Path | None) -> int:
        self.scans.append((domain, output))
        return self._scan_code

    def _open(self, uri: str) -> bool:
        self.opened.append(uri)
        return True

    def run(self) -> str:
        flow.run(
            input_fn=lambda _prompt: next(self._feed),
            print_fn=self.out.append,
            open_fn=self._open,
            scan_fn=self._scan,
        )
        return "\n".join(self.out)


def test_quit_immediately():
    session = Session("q")
    session.run()
    assert session.scans == []


def test_scan_uses_default_report_name_when_output_left_empty():
    session = Session("1", "example.com", "", "q")
    session.run()
    assert session.scans == [("example.com", Path("example.com-report.html"))]


@pytest.mark.parametrize(
    "typed",
    [
        "https://example.com",
        "https://example.com/",
        "HTTP://Example.com:8443/a/b?q=1#x",
        "https://user@example.com/",
        "example.com/path",
    ],
)
def test_scan_accepts_a_pasted_url_and_scans_its_hostname(typed: str):
    session = Session("1", typed, "", "q")
    session.run()
    assert session.scans == [("example.com", Path("example.com-report.html"))]


def test_non_url_garbage_is_left_for_the_scope_gate_to_refuse():
    session = Session("1", "not a domain", "", "q")
    session.run()
    assert [scan[0] for scan in session.scans] == ["not a domain"]


def test_scan_uses_the_chosen_output_path():
    session = Session("1", "example.com", "out.html", "q")
    session.run()
    assert session.scans == [("example.com", Path("out.html"))]


def test_open_last_report_after_a_successful_scan(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    report = tmp_path / "r.html"
    report.write_text("<html></html>", encoding="utf-8")
    session = Session("1", "example.com", str(report), "2", "q")
    session.run()
    assert session.opened == [report.resolve().as_uri()]


def test_open_report_without_scan_explains_and_opens_nothing():
    session = Session("2", "q")
    text = session.run()
    assert session.opened == []
    assert "No report yet" in text


def test_refused_scan_is_not_remembered_as_a_report():
    session = Session("1", "evil.test", "", "2", "q", scan_code=1)
    text = session.run()
    assert session.opened == []
    assert "No report yet" in text


def test_open_report_missing_on_disk_does_not_open(tmp_path: Path):
    gone = tmp_path / "gone.html"
    session = Session("1", "example.com", str(gone), "2", "q")
    text = session.run()
    assert session.opened == []
    assert "not found" in text


def test_info_entry_shows_the_passive_guarantee():
    session = Session("0", "q")
    text = session.run()
    assert "passive" in text.lower()
    assert "authorized" in text.lower()


# --- the default command goes through the real CLI: validation first, nothing bypassed ---------


def test_default_scan_refuses_a_non_domain_before_any_collection(tmp_path: Path, monkeypatch):
    def boom(*_args, **_kwargs):
        raise AssertionError("collection must not start for an invalid domain")

    monkeypatch.setattr("domain_mapper.cli._collect", boom)
    code = flow.default_scan("com", tmp_path / "r.html")
    assert code == 1
    assert not (tmp_path / "r.html").exists()


def test_default_scan_survives_an_unexpected_error(monkeypatch, capsys):
    def explode(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("domain_mapper.cli.scan", explode)
    assert flow.default_scan("example.com", None) == 2
    assert "disk full" in capsys.readouterr().err


def test_open_report_warns_when_no_browser_could_open_it(tmp_path: Path):
    report = tmp_path / "r.html"
    report.write_text("<html></html>", encoding="utf-8")
    out: list[str] = []
    flow._open_report(report, out.append, lambda _uri: False)
    assert any("Could not open" in line for line in out)
