import typer
from pkg_resources import get_distribution

from aleph_client.utils import AsyncTyper

app = AsyncTyper(no_args_is_help=True)


def get_version(value: bool):
    __version__ = "NaN"
    dist_name = "aleph-client"
    if value:
        try:
            __version__ = get_distribution(dist_name).version
        finally:
            typer.echo(f"Aleph CLI Version: {__version__}")
            raise typer.Exit()


@app.command()
def version():
    get_version(True)
