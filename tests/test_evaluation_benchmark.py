import subprocess
import sys

import pytest

from domain_mapper.evaluation.benchmark import (
    TOOL_COMMANDS,
    ToolFailedError,
    ToolNotInstalledError,
    ToolResult,
    compare,
    parse_subdomains,
    run_tool,
    subprocess_runner,
)
from domain_mapper.evaluation.sources import is_subdomain

APEX = "example.com"


def test_parse_keeps_only_real_subdomains_of_the_apex() -> None:
    text = "\n".join(
        [
            "A.Example.com",  # case folded
            "b.example.com.",  # trailing root dot stripped
            "  c.example.com  ",  # whitespace stripped
            "example.com",  # the apex is not a subdomain
            "notexample.com",  # look-alike: suffix test includes the dot
            "x.example.com.evil.org",  # apex in the middle only
            "*.example.com",  # wildcard record, not a host
            "",
            "garbage line with spaces",
            "a.example.com",  # duplicate
        ]
    )
    assert parse_subdomains(text, APEX) == frozenset(
        {"a.example.com", "b.example.com", "c.example.com"}
    )


def test_parse_takes_first_token_of_decorated_lines() -> None:
    # Some tools append resolution info after the name.
    assert parse_subdomains("a.example.com 192.0.2.1\n", APEX) == frozenset({"a.example.com"})


def test_run_tool_times_the_call_and_parses_output() -> None:
    calls: list[tuple[str, ...]] = []
    ticks = iter([10.0, 12.5])

    def runner(argv: tuple[str, ...]) -> str:
        calls.append(argv)
        return "a.example.com\nb.example.com\n"

    result = run_tool("subfinder", APEX, runner, clock=lambda: next(ticks))

    assert calls == [TOOL_COMMANDS["subfinder"](APEX)]
    assert result == ToolResult(
        name="subfinder",
        subdomains=frozenset({"a.example.com", "b.example.com"}),
        seconds=2.5,
        error=None,
    )


@pytest.mark.parametrize("name", ["amass", "subfinder"])
def test_tool_commands_are_passive_and_target_only_the_domain(name: str) -> None:
    argv = TOOL_COMMANDS[name](APEX)
    assert argv[0] == name
    assert APEX in argv
    assert any("passive" in part for part in argv) or name == "subfinder"
    # No active techniques: brute force, zone transfers, direct DNS probing.
    forbidden = {"-brute", "-active", "-bl", "-w"}
    assert not forbidden & set(argv)


def test_run_tool_records_a_missing_binary_instead_of_crashing() -> None:
    def runner(argv: tuple[str, ...]) -> str:
        raise ToolNotInstalledError(argv[0])

    result = run_tool("amass", APEX, runner, clock=lambda: 0.0)

    assert result.subdomains == frozenset()
    assert result.error == "amass is not installed"


def test_run_tool_rejects_an_unknown_tool() -> None:
    with pytest.raises(KeyError):
        run_tool("nmap", APEX, lambda argv: "", clock=lambda: 0.0)


def test_compare_reports_coverage_unique_finds_and_recall() -> None:
    results = [
        ToolResult(
            "domain-mapper", frozenset({"a.example.com", "b.example.com", "c.example.com"}), 30.0, None
        ),
        ToolResult("subfinder", frozenset({"b.example.com", "d.example.com"}), 8.0, None),
        ToolResult("amass", frozenset(), 0.0, "amass is not installed"),
    ]

    rows = {row.name: row for row in compare(results)}

    # Union of everything any tool found: a, b, c, d.
    assert rows["domain-mapper"].found == 3
    assert rows["domain-mapper"].unique == frozenset({"a.example.com", "c.example.com"})
    assert rows["domain-mapper"].recall == pytest.approx(3 / 4)
    assert rows["subfinder"].unique == frozenset({"d.example.com"})
    assert rows["subfinder"].recall == pytest.approx(2 / 4)
    assert rows["subfinder"].seconds == 8.0
    # A tool that failed is reported as failed, not as "found nothing".
    assert rows["amass"].error == "amass is not installed"
    assert rows["amass"].recall is None


def test_compare_with_no_findings_has_zero_recall_not_a_division_error() -> None:
    rows = compare([ToolResult("domain-mapper", frozenset(), 1.0, None)])
    assert rows[0].recall == 0.0


def test_subprocess_runner_returns_stdout_without_a_shell() -> None:
    out = subprocess_runner((sys.executable, "-c", "print('a.example.com')"))
    assert out.strip() == "a.example.com"


def test_subprocess_runner_raises_when_the_binary_is_missing() -> None:
    with pytest.raises(ToolNotInstalledError):
        subprocess_runner(("domain-mapper-no-such-binary", "-d", APEX))


def test_tool_commands_refuse_a_domain_that_would_become_a_flag() -> None:
    for bad in ("-oA", "example.com; rm -rf /", "a b.com", ""):
        with pytest.raises(ValueError, match="plain domain"):
            TOOL_COMMANDS["amass"](bad)


def test_run_tool_turns_a_timeout_into_an_error_result() -> None:
    def runner(argv: tuple[str, ...]) -> str:
        raise subprocess.TimeoutExpired(argv, 600)

    result = run_tool("amass", APEX, runner, clock=lambda: 0.0)

    assert result.subdomains == frozenset()
    assert result.error is not None
    assert "timed out" in result.error


def test_run_tool_turns_an_os_error_into_an_error_result() -> None:
    def runner(argv: tuple[str, ...]) -> str:
        raise PermissionError("denied")

    result = run_tool("amass", APEX, runner, clock=lambda: 0.0)

    assert result.error is not None
    assert "denied" in result.error


def test_a_failed_run_is_an_error_not_zero_findings_and_keeps_its_output() -> None:
    def runner(argv: tuple[str, ...]) -> str:
        raise ToolFailedError(2, "flag provided but not defined", stdout="partial\n")

    result = run_tool("subfinder", APEX, runner, clock=lambda: 0.0)

    assert result.error == "subfinder exited with status 2: flag provided but not defined"
    assert result.raw == "partial\n"
    assert compare([result])[0].recall is None


def test_run_tool_keeps_the_raw_stdout_without_it_affecting_equality() -> None:
    result = run_tool("subfinder", APEX, lambda argv: "a.example.com\n", clock=lambda: 0.0)
    assert result.raw == "a.example.com\n"
    assert result == ToolResult("subfinder", frozenset({"a.example.com"}), 0.0, None)


def test_subprocess_runner_raises_on_a_non_zero_exit() -> None:
    code = "import sys; print('out'); sys.stderr.write('boom'); sys.exit(3)"
    with pytest.raises(ToolFailedError) as info:
        subprocess_runner((sys.executable, "-c", code))
    assert info.value.returncode == 3
    assert "boom" in info.value.stderr
    assert info.value.stdout.strip() == "out"


def test_subprocess_runner_looks_only_in_the_explicit_search_path(tmp_path) -> None:
    name = "domain-mapper-fake-tool" + (".exe" if sys.platform == "win32" else "")
    # The binary is looked up only in the given directory, never in the ambient PATH.
    with pytest.raises(ToolNotInstalledError):
        subprocess_runner((name, "-d", APEX), search_path=str(tmp_path))


def test_domain_check_rejects_a_trailing_newline() -> None:
    with pytest.raises(ValueError, match="plain domain"):
        TOOL_COMMANDS["amass"]("example.com\n")


def test_is_subdomain_is_the_single_definition_used_by_both_modules() -> None:
    assert is_subdomain("a.example.com", APEX)
    assert not is_subdomain("example.com", APEX)
    assert not is_subdomain("notexample.com", APEX)
    assert not is_subdomain("a.example.com.evil.org", APEX)
