import sys

import pytest

from surfacemap.evaluation.benchmark import (
    TOOL_COMMANDS,
    ToolNotInstalledError,
    ToolResult,
    compare,
    parse_subdomains,
    run_tool,
    subprocess_runner,
)

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
            "surfacemap", frozenset({"a.example.com", "b.example.com", "c.example.com"}), 30.0, None
        ),
        ToolResult("subfinder", frozenset({"b.example.com", "d.example.com"}), 8.0, None),
        ToolResult("amass", frozenset(), 0.0, "amass is not installed"),
    ]

    rows = {row.name: row for row in compare(results)}

    # Union of everything any tool found: a, b, c, d.
    assert rows["surfacemap"].found == 3
    assert rows["surfacemap"].unique == frozenset({"a.example.com", "c.example.com"})
    assert rows["surfacemap"].recall == pytest.approx(3 / 4)
    assert rows["subfinder"].unique == frozenset({"d.example.com"})
    assert rows["subfinder"].recall == pytest.approx(2 / 4)
    assert rows["subfinder"].seconds == 8.0
    # A tool that failed is reported as failed, not as "found nothing".
    assert rows["amass"].error == "amass is not installed"
    assert rows["amass"].recall is None


def test_compare_with_no_findings_has_zero_recall_not_a_division_error() -> None:
    rows = compare([ToolResult("surfacemap", frozenset(), 1.0, None)])
    assert rows[0].recall == 0.0


def test_subprocess_runner_returns_stdout_without_a_shell() -> None:
    out = subprocess_runner((sys.executable, "-c", "print('a.example.com')"))
    assert out.strip() == "a.example.com"


def test_subprocess_runner_raises_when_the_binary_is_missing() -> None:
    with pytest.raises(ToolNotInstalledError):
        subprocess_runner(("surfacemap-no-such-binary", "-d", APEX))


def test_tool_commands_refuse_a_domain_that_would_become_a_flag() -> None:
    for bad in ("-oA", "example.com; rm -rf /", "a b.com", ""):
        with pytest.raises(ValueError, match="plain domain"):
            TOOL_COMMANDS["amass"](bad)
