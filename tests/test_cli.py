from pathlib import Path

import pytest
from typer.testing import CliRunner

from domain_mapper import __version__
from domain_mapper.cli import app

runner = CliRunner()


@pytest.fixture
def scope_file(tmp_path: Path) -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text(
        "authorized:\n  - domain: logan-villard.fr\n    authorization: owner\n",
        encoding="utf-8",
    )
    return path


def test_version_option() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


def test_scope_check_allowed(scope_file: Path) -> None:
    result = runner.invoke(
        app, ["scope", "check", "www.logan-villard.fr", "--scope-file", str(scope_file)]
    )
    assert result.exit_code == 0
    assert "ALLOWED" in result.output
    assert "www.logan-villard.fr" in result.output


def test_scope_check_refused(scope_file: Path) -> None:
    result = runner.invoke(
        app, ["scope", "check", "evil-logan-villard.fr", "--scope-file", str(scope_file)]
    )
    assert result.exit_code == 1
    assert "REFUSED" in result.output
    assert "not listed" in result.output


def test_scope_check_missing_file(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["scope", "check", "logan-villard.fr", "--scope-file", str(tmp_path / "nope.yaml")]
    )
    assert result.exit_code == 2
    assert "scope.example.yaml" in result.output


def test_scope_file_defaults_to_cwd(scope_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(scope_file.parent)
    result = runner.invoke(app, ["scope", "check", "logan-villard.fr"])
    assert result.exit_code == 0


def test_module_entry_point_exposes_app() -> None:
    import domain_mapper.__main__ as main_module

    assert main_module.app is app


def test_no_args_on_a_terminal_opens_the_menu(monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[bool] = []
    monkeypatch.setattr("domain_mapper.cli._stdin_is_tty", lambda: True)
    monkeypatch.setattr("domain_mapper.tui.main", lambda: opened.append(True))
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    assert opened == [True]


def test_no_args_without_a_terminal_shows_help(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("domain_mapper.cli._stdin_is_tty", lambda: False)
    result = runner.invoke(app, [])
    assert "Usage" in result.output
    assert "scan" in result.output


def test_subcommand_never_opens_the_menu(
    scope_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("domain_mapper.cli._stdin_is_tty", lambda: True)
    monkeypatch.setattr("domain_mapper.tui.main", lambda: pytest.fail("menu opened"))
    result = runner.invoke(app, ["scope", "check", "logan-villard.fr", "-s", str(scope_file)])
    assert result.exit_code == 0
