"""Run the passive benchmark on one authorized domain and write raw outputs + a Markdown table.

    python evaluation/run_benchmark.py logan-villard.fr --tool-dir <dir with amass/subfinder> \
        --out evaluation/results

Scope first: the domain must pass `scope.yaml` before anything is queried. Raw tool output is
saved untouched, so scoring changes are recomputed offline (`--rescore`), never by re-querying.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import time
from datetime import date
from pathlib import Path

from surfacemap.cli import _collect
from surfacemap.config import Settings
from surfacemap.evaluation.benchmark import (
    TOOL_COMMANDS,
    ToolNotInstalledError,
    ToolResult,
    compare,
    parse_subdomains,
    run_tool,
    subprocess_runner,
)
from surfacemap.evaluation.sources import subdomains_by_source
from surfacemap.scope import Scope


def surfacemap_result(domain: str, scope_file: Path, raw_path: Path) -> ToolResult:
    today = date.today()
    scope = Scope.load(scope_file)
    root = scope.require(domain, today=today)
    start = time.monotonic()
    graph = asyncio.run(_collect(root, scope, Settings(), today))
    seconds = time.monotonic() - start
    found = frozenset().union(*subdomains_by_source(graph, root).values())
    raw_path.write_text("\n".join(sorted(found)) + "\n", encoding="utf-8")
    return ToolResult("surfacemap", found, seconds, None)


def table(results: list[ToolResult]) -> str:
    lines = [
        "| tool | subdomains | only this tool | recall vs union | time (s) |",
        "|---|---|---|---|---|",
    ]
    for row in compare(results):
        recall = "n/a" if row.recall is None else f"{row.recall:.0%}"
        note = f" ({row.error})" if row.error else ""
        lines.append(
            f"| {row.name}{note} | {row.found} | {len(row.unique)} | {recall} | {row.seconds:.1f} |"
        )
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("domain")
    ap.add_argument("--scope-file", type=Path, default=Path("scope.yaml"))
    ap.add_argument("--tool-dir", type=Path, help="directory holding the amass/subfinder binaries")
    ap.add_argument("--out", type=Path, default=Path("evaluation/results"))
    ap.add_argument("--rescore", action="store_true", help="re-read saved raw outputs, no queries")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    results: list[ToolResult] = []
    if args.rescore:
        for raw in sorted(args.out.glob("*.txt")):
            text = raw.read_text(encoding="utf-8")
            results.append(ToolResult(raw.stem, parse_subdomains(text, args.domain), 0.0, None))
    else:
        if args.tool_dir:
            os.environ["PATH"] = f"{args.tool_dir}{os.pathsep}{os.environ['PATH']}"
        results.append(surfacemap_result(args.domain, args.scope_file, args.out / "surfacemap.txt"))
        for name in TOOL_COMMANDS:
            captured: list[str] = []

            def runner(argv: tuple[str, ...], _c: list[str] = captured) -> str:
                try:
                    out = subprocess_runner(argv)
                except ToolNotInstalledError:
                    raise
                _c.append(out)
                return out

            result = run_tool(name, args.domain, runner)
            if captured:
                (args.out / f"{name}.txt").write_text(captured[0], encoding="utf-8")
            results.append(result)

    report = table(results)
    (args.out / "results.md").write_text(report, encoding="utf-8")
    print(report)


if __name__ == "__main__":
    main()
