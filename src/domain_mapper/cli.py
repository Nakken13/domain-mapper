"""Command-line interface.

Exit codes for `scope check` and `scan`: 0 ok, 1 refused (invalid or out of scope), 2 unusable file.
"""

import asyncio
import sys
from collections.abc import Sequence
from datetime import date, timedelta
from pathlib import Path
from typing import Annotated

import typer

from domain_mapper import __version__
from domain_mapper.collect.cache import ResponseCache
from domain_mapper.collect.engine import Engine
from domain_mapper.collect.http import HttpClient
from domain_mapper.collect.ratelimit import RateLimiter
from domain_mapper.config import Settings
from domain_mapper.graph.builder import SurfaceGraph
from domain_mapper.models import Finding
from domain_mapper.plugins.base import PluginContext, ScopeView, default_registry
from domain_mapper.report import render_report
from domain_mapper.risk import Rule, RuleContext, run_rules
from domain_mapper.risk.certificates import CertificateRule
from domain_mapper.risk.email_auth import EmailAuthRule
from domain_mapper.risk.exposed_envs import ExposedEnvironmentRule
from domain_mapper.risk.hosting import HostingSprawlRule
from domain_mapper.risk.takeover import TakeoverRule
from domain_mapper.scope import InvalidDomainError, OutOfScopeError, Scope, ScopeFileError

app = typer.Typer(
    help="Passive attack-surface mapping from public sources only.",
)
scope_app = typer.Typer(help="Inspect the authorization scope.", no_args_is_help=True)
app.add_typer(scope_app, name="scope")

ScopeFileOption = Annotated[
    Path,
    typer.Option("--scope-file", "-s", help="Authorization file listing allowed domains."),
]


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"domain-mapper {__version__}")
        raise typer.Exit


def _stdin_is_tty() -> bool:
    return sys.stdin.isatty()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option(
            "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
        ),
    ] = False,
) -> None:
    """domain-mapper: passive sources only; only scan what you own or may assess.

    Without a command: opens the interactive menu on a terminal, otherwise prints this help.
    """
    if ctx.invoked_subcommand is not None:
        return
    if _stdin_is_tty():
        from domain_mapper import tui  # late import: the menu imports this module

        tui.main()
        return
    typer.echo(ctx.get_help())


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
        limiter = RateLimiter({})  # no per-source override: every source uses DEFAULT_LIMIT
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
    domain: Annotated[str, typer.Argument(help="Domain to map (passive sources only).")],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Report path (default: <domain>-report.html)."),
    ] = None,
    scope_file: Annotated[
        Path | None,
        typer.Option(
            "--scope-file",
            "-s",
            help="Optional authorization file (multi-domain, expiry). Default: scan DOMAIN alone.",
        ),
    ] = None,
) -> None:
    """Map DOMAIN from public sources and write a self-contained HTML report."""
    try:
        scope = Scope.load(scope_file) if scope_file else Scope.for_domain(domain)
    except ScopeFileError as exc:
        typer.secho(f"ERROR {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc
    except InvalidDomainError as exc:
        typer.secho(f"REFUSED {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1) from exc

    today = date.today()
    try:
        # Validate first: nothing below (cache, HTTP client, plugins) exists before this passes.
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
