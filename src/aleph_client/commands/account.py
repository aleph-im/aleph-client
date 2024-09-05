from __future__ import annotations

import asyncio
import base64
import logging
import sys
from pathlib import Path
from typing import Optional

import aiohttp
import typer
from aleph.sdk.account import _load_account
from aleph.sdk.chains.common import generate_key
from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.conf import settings
from aleph.sdk.types import AccountFromPrivateKey
from typer.colors import RED

from aleph_client.commands import help_strings
from aleph_client.commands.utils import setup_logging
from aleph_client.utils import AsyncTyper

logger = logging.getLogger(__name__)
app = AsyncTyper(no_args_is_help=True)


@app.command()
def create(
    private_key: Optional[str] = typer.Option(None, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(None, help=help_strings.PRIVATE_KEY_FILE),
    replace: bool = False,
    debug: bool = False,
):
    """Create or import a private key."""

    setup_logging(debug)

    if private_key_file is None:
        private_key_file = Path(typer.prompt("Enter file in which to save the key", settings.PRIVATE_KEY_FILE))

    if private_key_file.exists() and not replace:
        typer.secho(f"Error: key already exists: '{private_key_file}'", fg=RED)

        raise typer.Exit(1)

    private_key_bytes: bytes
    if private_key is not None:
        # Validate the private key bytes by instantiating an account.
        _load_account(private_key_str=private_key, account_type=ETHAccount)
        private_key_bytes = bytes.fromhex(private_key)
    else:
        private_key_bytes = generate_key()

    if not private_key_bytes:
        typer.secho("An unexpected error occurred!", fg=RED)
        raise typer.Exit(2)

    private_key_file.parent.mkdir(parents=True, exist_ok=True)
    private_key_file.write_bytes(private_key_bytes)
    typer.secho(f"Private key stored in {private_key_file}", fg=RED)


@app.command()
def address(
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
):
    """
    Display your public address.
    """

    if private_key is not None:
        private_key_file = None
    elif private_key_file and not private_key_file.exists():
        typer.secho("No private key available", fg=RED)
        raise typer.Exit(code=1)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)
    typer.echo(account.get_address())


@app.command()
def export_private_key(
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
):
    """
    Display your private key.
    """

    if private_key is not None:
        private_key_file = None
    elif private_key_file and not private_key_file.exists():
        typer.secho("No private key available", fg=RED)
        raise typer.Exit(code=1)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)
    if hasattr(account, "private_key"):
        private_key_hex: str = base64.b16encode(account.private_key).decode().lower()
        typer.echo(f"0x{private_key_hex}")
    else:
        typer.secho(f"Private key cannot be read for {account}", fg=RED)


@app.command()
def path():
    if settings.PRIVATE_KEY_FILE:
        typer.echo(settings.PRIVATE_KEY_FILE)


@app.command("sign-bytes")
def sign_bytes(
    message: Optional[str] = typer.Option(None, help="Message to sign"),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    """Sign a message using your private key."""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    if message is None:
        # take from stdin
        message = "\n".join(sys.stdin.readlines())

    coroutine = account.sign_raw(message.encode())
    signature = asyncio.run(coroutine)
    typer.echo(signature.hex())


@app.command()
async def balance(
    address: Optional[str] = typer.Option(None, help="Address"),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
):
    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    if account and not address:
        address = account.get_address()

    if address:
        uri = f"{settings.API_HOST}/api/v0/addresses/{address}/balance"

        async with aiohttp.ClientSession() as session:
            response = await session.get(uri)
            if response.status == 200:
                balance_data = await response.json()
                balance_data["available_amount"] = balance_data["balance"] - balance_data["locked_amount"]
                typer.echo(
                    "\n"
                    + f"Address: {balance_data['address']}\n"
                    + f"Balance: {balance_data['balance']:.2f}".rstrip("0").rstrip(".")
                    + "\n"
                    + f" - Locked: {balance_data['locked_amount']:.2f}".rstrip("0").rstrip(".")
                    + "\n"
                    + f" - Available: {balance_data['available_amount']:.2f}".rstrip("0").rstrip(".")
                    + "\n"
                )
            else:
                typer.echo(f"Failed to retrieve balance for address {address}. Status code: {response.status}")
    else:
        typer.echo("Error: Please provide either a private key, private key file, or an address.")
