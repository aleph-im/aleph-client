from __future__ import annotations

import asyncio
import base64
import json
import logging
import sys
from pathlib import Path
from typing import Optional

import aiohttp
import typer
from aleph.sdk.account import (
    CHAIN_TO_ACCOUNT_MAP,
    _load_account,
    detect_chain_from_private_key,
)
from aleph.sdk.chains.common import generate_key, generate_key_solana
from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.chains.solana import SOLAccount
from aleph.sdk.conf import settings
from aleph.sdk.types import AccountFromPrivateKey, ChainAccount
from aleph.sdk.utils import (
    add_chain_account,
    get_chain_account,
    load_json,
    parse_solana_private_key,
    update_chain_account,
)
from aleph_message.models import Chain
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from typer.colors import RED

from aleph_client.commands import help_strings
from aleph_client.commands.utils import setup_logging
from aleph_client.utils import AsyncTyper, list_unlinked_keys

logger = logging.getLogger(__name__)
app = AsyncTyper(no_args_is_help=True)
console = Console()


@app.command()
async def create(
    private_key: Optional[str] = typer.Option(None, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(None, help=help_strings.PRIVATE_KEY_FILE),
    type: Optional[Chain] = typer.Option(default=None, help=help_strings.ACCOUNT_CHAIN),
    name: Optional[str] = typer.Option(default=None, help="Name for account handling"),
    replace: bool = False,
    debug: bool = False,
):
    """Create or import a private key."""

    setup_logging(debug)

    try:
        if settings.CONFIG_FILE.exists() and settings.CONFIG_FILE.stat().st_size > 0:
            with open(settings.CONFIG_FILE, "r") as f:
                chain_accounts = json.load(f)
        else:
            chain_accounts = []
    except (FileNotFoundError, json.JSONDecodeError) as e:
        typer.secho(f"Error loading config file: {e}", fg=RED)
        raise typer.Exit(1)

    if private_key_file is None:
        private_key_file = Path(typer.prompt("Enter file in which to save the key", settings.PRIVATE_KEY_FILE))

    if private_key_file.exists() and not replace:
        typer.secho(f"Error: key already exists: '{private_key_file}'", fg=RED)
        raise typer.Exit(1)

    existing_account = next((acc for acc in chain_accounts if acc["path"] == str(private_key_file)), None)
    if existing_account and not replace:
        typer.secho(f"Error: key already exists: '{private_key_file}'", fg=RED)
        raise typer.Exit(1)

    private_key_bytes: bytes
    if private_key is not None:

        private_key_type: Chain = detect_chain_from_private_key(private_key)
        account_class = CHAIN_TO_ACCOUNT_MAP.get(private_key_type, ETHAccount)

        _load_account(private_key_str=private_key, account_type=account_class)
        if private_key_type == Chain.ETH:
            private_key_bytes = bytes.fromhex(private_key)
        else:
            private_key_bytes = parse_solana_private_key(private_key)

    else:
        if not type:
            type = Chain(
                Prompt.ask(
                    "Which chain u want to be loaded as: ",
                    choices=[Chain.ETH, Chain.SOL, Chain.AVAX, Chain.BASE],
                    default=Chain.ETH.value,
                )
            )

        if type.SOL:
            private_key_bytes = generate_key_solana()
        else:
            private_key_bytes = generate_key()

    if not private_key_bytes:
        typer.secho("An unexpected error occurred!", fg=RED)
        raise typer.Exit(2)
    if name is None:
        name = Prompt.ask(
            "Which name u want use for private key: ",
        )

    private_key_file.parent.mkdir(parents=True, exist_ok=True)
    private_key_file.write_bytes(private_key_bytes)
    typer.secho(f"Private key stored in {private_key_file}", fg=RED)
    account = ChainAccount(name=name, path=private_key_file, chain=type if type else Chain.ETH)
    await add_chain_account(account)
    typer.secho(f"Account stored with name : {account.name} on chain {account.chain}", fg=RED)


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


@app.command()
async def list():
    """List all chain accounts from the config file."""

    chain_accounts = await load_json(settings.CONFIG_FILE)

    table = Table(title="Chain Accounts", show_lines=True)

    table.add_column("Name", justify="left", style="cyan", no_wrap=True)
    table.add_column("Path", justify="left", style="green")
    table.add_column("Chain", justify="left", style="magenta")

    for account in chain_accounts:
        table.add_row(account["name"], account["path"], account["chain"])

    # Print the table
    console.print(table)


@app.command()
async def config(
    key_file: Optional[Path] = typer.Option(None, help="Path to the private key file"),
    chain_type: Optional[str] = typer.Option(None, help="Type of blockchain (ETH, SOL, etc.)"),
):
    """
    Async command to link private keys to a blockchain, interactively or non-interactively.
    """

    if key_file is None:
        unlinked_keys = await list_unlinked_keys()
        if not unlinked_keys:
            typer.secho("No unlinked private keys found.", fg=typer.colors.GREEN)
            raise typer.Exit()

        console.print("[bold cyan]Available unlinked private keys:[/bold cyan]")
        for idx, key in enumerate(unlinked_keys, start=1):
            console.print(f"[{idx}] {key.name}")

        key_choice = Prompt.ask("Choose a private key by entering the number or name")

        if key_choice.isdigit():
            key_index = int(key_choice) - 1
            if 0 <= key_index < len(unlinked_keys):
                key_file = unlinked_keys[key_index]
            else:
                typer.secho("Invalid key index selected.", fg=typer.colors.RED)
                raise typer.Exit()
        else:
            matching_keys = [key for key in unlinked_keys if key.name == key_choice]
            if matching_keys:
                key_file = matching_keys[0]
            else:
                typer.secho("No matching key found with the provided name.", fg=typer.colors.RED)
                raise typer.Exit()

    if chain_type is None:
        chain_type = Prompt.ask(
            "Which chain type do you want to link the key to?",
            choices=["ETH", "SOL", "AVAX", "BASE", "BSC"],
            default="ETH",
        )

    typer.secho(f"Private key file: {key_file}", fg=typer.colors.YELLOW)
    typer.secho(f"Chain type: {chain_type}", fg=typer.colors.YELLOW)

    new_account = ChainAccount(name=key_file.stem, path=key_file, chain=Chain(chain_type))

    try:
        await add_chain_account(new_account)
        typer.secho(f"Key file {key_file} linked to {chain_type} successfully.", fg=typer.colors.GREEN)
    except ValueError as e:
        typer.secho(f"Error: {e}", fg=typer.colors.RED)


@app.command()
async def update(
    name: str = typer.Option(..., help="The name of the account to update"),
    key_file: Optional[Path] = typer.Option(None, help="The new path to the private key file"),
    chain_type: Optional[str] = typer.Option(None, help="The new blockchain type (ETH, SOL, etc.)"),
):
    """
    Command to update an existing chain account.
    """

    try:
        existing_account = await get_chain_account(name)

        new_key_file = key_file if key_file else existing_account.path
        new_chain_type = chain_type if chain_type else existing_account.chain

        updated_account = ChainAccount(name=name, path=new_key_file, chain=Chain(new_chain_type))

        await update_chain_account(updated_account)

        typer.secho(f"Account {name} updated successfully!", fg=typer.colors.GREEN)

    except ValueError as e:
        typer.secho(f"Error: {e}", fg=typer.colors.RED)
