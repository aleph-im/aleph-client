from __future__ import annotations

from importlib.metadata import version as importlib_version

import typer

from aleph_client.utils import AsyncTyper

app = AsyncTyper(no_args_is_help=True)


def get_version(value: bool):
    __version__ = "NaN"
    dist_name = "aleph-client"
    if value:
        try:
            __version__ = importlib_version(dist_name)
        finally:
            typer.echo(f"Aleph CLI Version: {__version__}")
            raise typer.Exit(1)


@app.command()
def version():
    get_version(True)
