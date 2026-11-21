"""Benchmark harness: domain-mapper against Amass and Subfinder, passive mode only.

Scoring is pure (parse, compare). The only I/O is the `Runner`, injected so tests never spawn a
process; `subprocess_runner` is the real one. Every external command is passive: no brute
force, no zone transfer, no direct DNS probing of the target.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field

from domain_mapper.evaluation.sources import is_subdomain

Runner = Callable[[tuple[str, ...]], str]
Clock = Callable[[], float]

_DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$")
_HOSTNAME_RE = re.compile(
    r"^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$"
)


class ToolNotInstalledError(RuntimeError):
    """The external tool's binary is not on PATH."""


class ToolFailedError(RuntimeError):
    """The tool ran but exited non-zero: empty output then means failure, not "found nothing"."""

    def __init__(self, returncode: int, stderr: str, stdout: str = "") -> None:
        super().__init__(f"exited with status {returncode}: {stderr.strip()[:200]}")
        self.returncode = returncode
        self.stderr = stderr
        self.stdout = stdout


def _checked(domain: str) -> str:
    """Reject anything that is not a plain domain: it ends up in an argv, `-x` would be a flag."""
    if not _DOMAIN_RE.fullmatch(domain):
        raise ValueError(f"not a plain domain name: {domain!r}")
    return domain


def _subfinder(domain: str) -> tuple[str, ...]:
    # Subfinder only queries passive sources; there is no active mode to turn off.
    return ("subfinder", "-d", _checked(domain), "-silent")


def _amass(domain: str) -> tuple[str, ...]:
    return ("amass", "enum", "-passive", "-d", _checked(domain))


TOOL_COMMANDS: Mapping[str, Callable[[str], tuple[str, ...]]] = {
    "subfinder": _subfinder,
    "amass": _amass,
}


@dataclass(frozen=True)
class ToolResult:
    name: str
    subdomains: frozenset[str]
    seconds: float
    error: str | None
    # Raw stdout, kept so a run is never lost; not part of the result's identity.
    raw: str = field(default="", compare=False, repr=False)


@dataclass(frozen=True)
class Coverage:
    name: str
    found: int
    unique: frozenset[str]
    recall: float | None  # None when the tool failed: "found nothing" would be a lie
    seconds: float
    error: str | None


def parse_subdomains(text: str, apex: str) -> frozenset[str]:
    """Normalise a tool's output to the set of real subdomains of `apex`.

    Same rules as the per-source counts: the apex itself, look-alikes (`notexample.com`),
    wildcards and junk are dropped, so tool noise cannot inflate a score.
    """
    found: set[str] = set()
    for line in text.splitlines():
        tokens = line.split()
        if not tokens:
            continue
        name = tokens[0].lower().rstrip(".")
        if is_subdomain(name, apex) and _HOSTNAME_RE.fullmatch(name):
            found.add(name)
    return frozenset(found)


def subprocess_runner(
    argv: tuple[str, ...], timeout: float = 600.0, search_path: str | None = None
) -> str:
    """Run `argv` (no shell) and return stdout.

    `search_path` is where to look for the binary (default: PATH), so the caller never has to
    mutate the process environment. Raises `ToolNotInstalledError` if absent and
    `ToolFailedError` on a non-zero exit.
    """
    exe = shutil.which(argv[0], path=search_path)
    if exe is None:
        raise ToolNotInstalledError(argv[0])
    done = subprocess.run(  # noqa: S603  (argv list, no shell, domain validated)
        (exe, *argv[1:]), capture_output=True, text=True, timeout=timeout, check=False
    )
    if done.returncode != 0:
        raise ToolFailedError(done.returncode, done.stderr, done.stdout)
    return done.stdout


def run_tool(name: str, domain: str, runner: Runner, clock: Clock = time.monotonic) -> ToolResult:
    """Run one passive tool against `domain`, timing it.

    Every way a run can go wrong (missing binary, crash, timeout, OS error) is a result with
    `error` set, never an exception: one failing tool must not lose the others' data.
    """
    argv = TOOL_COMMANDS[name](domain)
    start = clock()
    try:
        output = runner(argv)
    except ToolNotInstalledError:
        return ToolResult(name, frozenset(), 0.0, f"{name} is not installed")
    except ToolFailedError as exc:
        return ToolResult(name, frozenset(), clock() - start, f"{name} {exc}", raw=exc.stdout)
    except subprocess.TimeoutExpired:
        return ToolResult(name, frozenset(), clock() - start, f"{name} timed out")
    except OSError as exc:
        return ToolResult(name, frozenset(), clock() - start, f"{name} could not run: {exc}")
    return ToolResult(name, parse_subdomains(output, domain), clock() - start, None, raw=output)


def compare(results: Iterable[ToolResult]) -> list[Coverage]:
    """Coverage per tool: how many subdomains, how many only it found, recall vs the union.

    The union of what all tools found is the only ground truth available on a real target, so
    recall is relative: it ranks the tools, it does not claim to measure the true surface.
    """
    results = list(results)
    union: frozenset[str] = frozenset().union(*(r.subdomains for r in results))
    rows: list[Coverage] = []
    for r in results:
        others = frozenset().union(*(o.subdomains for o in results if o is not r))
        recall = None if r.error else (len(r.subdomains) / len(union) if union else 0.0)
        rows.append(
            Coverage(r.name, len(r.subdomains), r.subdomains - others, recall, r.seconds, r.error)
        )
    return rows
