"""
Aleph Client command-line interface.
"""

import typer

from aleph_client.utils import AsyncTyper
from .commands import about, account, aggregate, files, message, program

app = AsyncTyper()


@app.callback()
def common(
    ctx: typer.Context,
    version: bool = typer.Option(None, "--version", callback=about.get_version, help="Show Aleph CLI Version"),
    v: bool = typer.Option(None, "-v", callback=about.get_version, help="Show Aleph CLI Version"),
):
    pass


app.add_typer(account.app, name="account", help="Manage account")
app.add_typer(
    aggregate.app, name="aggregate", help="Manage aggregate messages on aleph.im"
)
app.add_typer(
    files.app, name="file", help="File uploading and pinning on IPFS and aleph.im"
)
app.add_typer(
    message.app,
    name="message",
    help="Post, amend, watch and forget messages on aleph.im",
)
app.add_typer(
    program.app, name="program", help="Upload and update programs on aleph.im VM"
)
app.add_typer(
    about.app, name="about", help="Display the informations of Aleph CLI"
)


if __name__ == "__main__":
    app()
