"""Command-line interface.

Exit codes for `scope check`: 0 allowed, 1 refused, 2 unusable scope file.
"""

from pathlib import Path
from typing import Annotated

import typer

from surfacemap import __version__
from surfacemap.scope import Scope, ScopeFileError

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
