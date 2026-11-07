"""Command line interface."""

from importlib.metadata import PackageNotFoundError, version
from typing import Annotated

import typer

EXIT_USAGE = 2

# Plain rendering keeps help and errors free of Rich panels, whose box drawing depends on
# the terminal encoding, and of tracebacks that print local variables.
app = typer.Typer(
    add_completion=False,
    pretty_exceptions_enable=False,
    rich_markup_mode=None,
    subcommand_metavar="",
)


def _print_version(requested: bool) -> None:
    if not requested:
        return
    try:
        installed = version("gazua")
    except PackageNotFoundError:
        typer.echo(
            "Gazua's package metadata is missing, so this installation is broken. "
            "Reinstall it with pip or uv.",
            err=True,
        )
        raise typer.Exit(EXIT_USAGE) from None
    typer.echo(f"gazua {installed}")
    raise typer.Exit


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    _version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Show the installed version and exit.",
            callback=_print_version,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """Security test suite for AI agents: proves in code whether an attack had a real effect."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


def main() -> int:
    app(prog_name="gazua")
    return 0
