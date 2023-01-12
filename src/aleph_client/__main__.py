"""
Aleph Client command-line interface.
"""

import os
from typing import Optional
from pathlib import Path

import typer

from aleph_client.types import AccountFromPrivateKey
from aleph_client.account import _load_account
from aleph_client.conf import settings
from .commands import files, message, program, help_strings, aggregate, account


app = typer.Typer()

app.add_typer(
    files.app, name="file", help="File uploading and pinning on IPFS and Aleph.im"
)
app.add_typer(
    message.app,
    name="message",
    help="Post, amend, watch and forget messages on Aleph.im",
)
app.add_typer(
    program.app, name="program", help="Upload and update programs on Aleph's VM"
)
app.add_typer(
    aggregate.app, name="aggregate", help="Manage aggregate messages on Aleph.im"
)

app.add_typer(account.app, name="account", help="Manage account")


@app.command()
def whoami(
    private_key: Optional[str] = typer.Option(
        settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY
    ),
    private_key_file: Optional[Path] = typer.Option(
        settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE
    ),
):
    """
    Display your public address.
    """

    if private_key is not None:
        private_key_file = None
    elif private_key_file and not os.path.exists(private_key_file):
        exit(0)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)
    typer.echo(account.get_address())


if __name__ == "__main__":
    app()
