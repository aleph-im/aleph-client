import os
import typer
import logging
from typing import Optional
from aleph_client.types import AccountFromPrivateKey
from aleph_client.chains.common import generate_key
from aleph_client.account import _load_account
from aleph_client.conf import settings

from aleph_client.commands import help_strings
from aleph_client.commands.utils import setup_logging


logger = logging.getLogger(__name__)
app = typer.Typer()


@app.command()
def create(
    from_private_key: Optional[str] = typer.Option(None, help=help_strings.PRIVATE_KEY),
    debug: bool = False,
):
    """Create or import a private key."""

    setup_logging(debug)

    typer.echo("Generating private key file.")
    private_key_file = typer.prompt(
        "Enter file in which to save the key", settings.PRIVATE_KEY_FILE
    )

    if os.path.exists(private_key_file):
        typer.echo(f"Error: key already exists: '{private_key_file}'")
        exit(1)

    private_key = None
    if from_private_key is not None:
        account: AccountFromPrivateKey = _load_account(private_key_str=from_private_key)
        private_key = from_private_key.encode()
    else:
        private_key = generate_key()

    if private_key is None:
        typer.echo("An unexpected error occurred!")
        exit(1)

    os.makedirs(os.path.dirname(private_key_file), exist_ok=True)
    with open(private_key_file, "wb") as prvfile:
        prvfile.write(private_key)
        typer.echo(f"Private key created => {private_key_file}")
