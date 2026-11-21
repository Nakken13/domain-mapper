"""Command-line interface.

Exit codes for `scope check` and `scan`: 0 ok, 1 refused (out of scope), 2 unusable scope file.
"""

import asyncio
from collections.abc import Sequence
from datetime import date, timedelta
from pathlib import Path
from typing import Annotated

import typer

from surfacemap import __version__
from surfacemap.collect.cache import ResponseCache
from surfacemap.collect.engine import Engine
from surfacemap.collect.http import HttpClient
from surfacemap.collect.ratelimit import RateLimiter
from surfacemap.config import Settings
from surfacemap.graph.builder import SurfaceGraph
from surfacemap.models import Finding
from surfacemap.plugins.base import PluginContext, ScopeView, default_registry
from surfacemap.report import render_report
from surfacemap.risk import Rule, RuleContext, run_rules
from surfacemap.risk.certificates import CertificateRule
from surfacemap.risk.email_auth import EmailAuthRule
from surfacemap.risk.exposed_envs import ExposedEnvironmentRule
from surfacemap.risk.hosting import HostingSprawlRule
from surfacemap.risk.takeover import TakeoverRule
from surfacemap.scope import OutOfScopeError, Scope, ScopeFileError

app = typer.Typer(
    help="Passive attack-surface mapping, restricted to domains listed in scope.yaml.",
    no_args_is_help=True,
)
scope_app = typer.Typer(help="Inspect the authorization scope.", no_args_is_help=True)
app.add_typer(scope_app, name="scope")

ScopeFileOption = Annotated[
    Path,
    typer.Option("--scope-file", "-s", help="Authorization file listing allowed domains."),
]


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"surfacemap {__version__}")
        raise typer.Exit


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
        ),
    ] = False,
) -> None:
    """SurfaceMap: passive sources only, authorized domains only."""


@scope_app.command("check")
def scope_check(
    domain: Annotated[str, typer.Argument(help="Domain to check against the scope file.")],
    scope_file: ScopeFileOption = Path("scope.yaml"),
) -> None:
    """Tell whether DOMAIN is covered by a valid authorization."""
    try:
        scope = Scope.load(scope_file)
    except ScopeFileError as exc:
        typer.secho(f"ERROR {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    decision = scope.check(domain)
    if decision.allowed:
        typer.secho(f"ALLOWED {decision.domain} ({decision.reason})", fg=typer.colors.GREEN)
        return
    typer.secho(f"REFUSED {domain} ({decision.reason})", fg=typer.colors.RED)
    raise typer.Exit(code=1)


CACHE_TTL = timedelta(hours=24)


def _default_rules() -> Sequence[Rule]:
    return (
        CertificateRule(),
        EmailAuthRule(),
        ExposedEnvironmentRule(),
        HostingSprawlRule(),
        TakeoverRule(),
    )


async def _collect(domain: str, scope: Scope, settings: Settings, today: date) -> SurfaceGraph:
    """Run the passive plugins from `domain`. Opened only after the scope check passed."""
    view = ScopeView(scope, today)
    with ResponseCache(settings.cache_dir / "cache.sqlite", ttl=CACHE_TTL) as cache:
        limiter = RateLimiter({})
        http = HttpClient(limiter, cache, view.is_target_host)
        try:
            ctx = PluginContext(
                http=http, cache=cache, limiter=limiter, settings=settings, scope=view
            )
            return await Engine(default_registry(), ctx).run(domain)
        finally:
            await http.aclose()


@app.command("scan")
def scan(
    domain: Annotated[str, typer.Argument(help="Authorized domain to map (passive sources only).")],
    scope_file: ScopeFileOption = Path("scope.yaml"),
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Report path (default: <domain>-report.html)."),
    ] = None,
) -> None:
    """Map DOMAIN from public sources and write a self-contained HTML report."""
    try:
        scope = Scope.load(scope_file)
    except ScopeFileError as exc:
        typer.secho(f"ERROR {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc

    today = date.today()
    try:
        # Scope first: nothing below (cache, HTTP client, plugins) exists before this passes.
        root = scope.require(domain, today=today)
    except OutOfScopeError as exc:
        typer.secho(f"REFUSED {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc

    target = output or Path(f"{root}-report.html")
    # Fail before the (slow, rate-limited) collection: its results would be lost otherwise.
    if target.is_dir() or not target.resolve().parent.is_dir():
        typer.secho(
            f"ERROR output path {target} is a directory or its folder does not exist",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)

    graph = asyncio.run(_collect(root, scope, Settings(), today))
    findings: tuple[Finding, ...] = run_rules(
        RuleContext(graph=graph, today=today), _default_rules()
    )
    target.write_text(render_report(graph, findings, domain=root), encoding="utf-8")
    typer.secho(
        f"OK {root}: {len(graph.nodes)} nodes, {len(findings)} findings -> {target}",
        fg=typer.colors.GREEN,
    )
