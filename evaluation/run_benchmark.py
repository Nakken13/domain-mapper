"""Run the passive benchmark on one authorized domain and write raw outputs + a Markdown table.

    python evaluation/run_benchmark.py logan-villard.fr --tool-dir <dir with amass/subfinder> \
        --out evaluation/results

Scope first: the domain must pass `scope.yaml` before anything is queried, and the normalised
domain it returns is the one every tool receives. Raw tool output, timings and errors are saved,
so scoring changes are recomputed offline (`--rescore`), never by querying again.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from datetime import date
from functools import partial
from pathlib import Path

from surfacemap.cli import _collect
from surfacemap.config import Settings
from surfacemap.evaluation.benchmark import (
    TOOL_COMMANDS,
    ToolResult,
    compare,
    parse_subdomains,
    run_tool,
    subprocess_runner,
)
from surfacemap.evaluation.sources import subdomains_by_source
from surfacemap.scope import OutOfScopeError, Scope, ScopeFileError

META = "results.json"  # {tool: {"seconds": float, "error": str | null}}


def surfacemap_result(root: str, scope: Scope, out: Path, today: date) -> ToolResult:
    start = time.monotonic()
    graph = asyncio.run(_collect(root, scope, Settings(), today))
    seconds = time.monotonic() - start
    by_source = subdomains_by_source(graph, root)
    found = frozenset().union(*by_source.values())
    raw = "\n".join(sorted(found)) + "\n"
    # Which plugin saw what: the data behind the per-source counts for this run.
    per_source = {source: sorted(fqdns) for source, fqdns in sorted(by_source.items())}
    (out / "surfacemap-by-source.json").write_text(json.dumps(per_source, indent=2) + "\n")
    return ToolResult("surfacemap", found, seconds, None, raw=raw)


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


def save(results: list[ToolResult], out: Path) -> None:
    meta = {r.name: {"seconds": r.seconds, "error": r.error} for r in results}
    (out / META).write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    for r in results:
        (out / f"{r.name}.txt").write_text(r.raw, encoding="utf-8")


def rescored(root: str, out: Path) -> list[ToolResult]:
    """Rebuild results from saved files only. Only tools listed in META count (no stale files)."""
    meta = json.loads((out / META).read_text(encoding="utf-8"))
    results = []
    for name, info in meta.items():
        raw = (out / f"{name}.txt").read_text(encoding="utf-8")
        results.append(
            ToolResult(name, parse_subdomains(raw, root), info["seconds"], info["error"], raw=raw)
        )
    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("domain")
    ap.add_argument("--scope-file", type=Path, default=Path("scope.yaml"))
    ap.add_argument("--tool-dir", type=Path, help="directory holding the amass/subfinder binaries")
    ap.add_argument("--out", type=Path, default=Path("evaluation/results"))
    ap.add_argument("--rescore", action="store_true", help="re-read saved outputs, no queries")
    args = ap.parse_args()

    today = date.today()
    try:
        scope = Scope.load(args.scope_file)
        # Scope first, in every mode. `root` is the normalised domain used from here on.
        root = scope.require(args.domain, today=today)
    except ScopeFileError as exc:
        print(f"ERROR {exc}", file=sys.stderr)
        return 2
    except OutOfScopeError as exc:
        print(f"REFUSED {exc}", file=sys.stderr)
        return 1

    args.out.mkdir(parents=True, exist_ok=True)
    if args.rescore:
        results = rescored(root, args.out)
    else:
        search_path = os.environ.get("PATH", "")
        if args.tool_dir:
            search_path = f"{args.tool_dir}{os.pathsep}{search_path}"
        runner = partial(subprocess_runner, search_path=search_path)
        results = [surfacemap_result(root, scope, args.out, today)]
        results += [run_tool(name, root, runner) for name in TOOL_COMMANDS]
        save(results, args.out)

    report = table(results)
    (args.out / "results.md").write_text(report, encoding="utf-8")
    print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
