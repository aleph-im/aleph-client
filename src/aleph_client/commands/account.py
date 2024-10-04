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
from aleph.sdk.account import _load_account
from aleph.sdk.chains.common import generate_key
from aleph.sdk.chains.solana import parse_private_key as parse_solana_private_key
from aleph.sdk.conf import (
    MainConfiguration,
    load_main_configuration,
    save_main_configuration,
    settings,
)
from aleph.sdk.types import AccountFromPrivateKey
from aleph_message.models import Chain
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from typer.colors import GREEN, RED

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
    chain_type: Optional[Chain] = typer.Option(default=None, help=help_strings.ACCOUNT_CHAIN),
    replace: bool = False,
    debug: bool = False,
):
    """Create or import a private key."""

    setup_logging(debug)

    try:
        if settings.CONFIG_FILE.exists() and settings.CONFIG_FILE.stat().st_size > 0:
            with open(settings.CONFIG_FILE, "r", encoding="utf-8") as f:
                current_account = json.load(f)
        else:
            current_account = {}
    except (FileNotFoundError, json.JSONDecodeError) as e:
        typer.secho(f"Error loading config file: {e}", fg=RED)
        raise typer.Exit(1)

    if private_key_file is None:
        private_key_file = Path(
            typer.prompt("Enter a filename for your new private key", settings.PRIVATE_KEY_FILE.name)
        )
    if not private_key_file.name.endswith(".key"):
        private_key_file = private_key_file.with_suffix(".key")
    if private_key_file.parent.as_posix() == ".":
        private_key_file = Path(settings.CONFIG_HOME, "private-keys", private_key_file)

    if private_key_file.exists() and not replace:
        typer.secho(f"Error: private key file already exists: '{private_key_file}'", fg=RED)
        raise typer.Exit(1)

    existing_account = "path" in current_account and current_account["path"] == private_key_file.as_posix()
    if existing_account and not replace:
        typer.secho(f"Error: private key account already loaded: '{private_key_file}'", fg=RED)
        raise typer.Exit(1)

    private_key_bytes: bytes
    if private_key is not None:
        if chain_type == Chain.SOL:
            private_key_bytes = parse_solana_private_key(private_key)
        else:
            private_key_bytes = bytes.fromhex(private_key)

    else:
        if replace and not chain_type:
            chain_type = Chain(
                Prompt.ask(
                    "Select the default chain to load: ",
                    choices=[Chain.ETH, Chain.AVAX, Chain.BASE, Chain.SOL],
                    default=Chain.ETH.value,
                )
            )
        private_key_bytes = generate_key()

    if not private_key_bytes:
        typer.secho("An unexpected error occurred!", fg=RED)
        raise typer.Exit(2)

    private_key_file.parent.mkdir(parents=True, exist_ok=True)
    private_key_file.write_bytes(private_key_bytes)
    typer.secho(f"Private key stored in {private_key_file}", fg=RED)
    account = MainConfiguration(path=private_key_file, chain=chain_type if chain_type else Chain.ETH)
    if replace:
        save_main_configuration(settings.CONFIG_FILE, account)
        typer.secho(f"Private key {account.path} on chain {account.chain} is now your default configuration", fg=GREEN)


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
        typer.echo("Enter the message to sign (type 'EOF' to stop):")
        lines = []
        while True:
            line = sys.stdin.readline().strip()
            if line == "EOF":
                break
            lines.append(line)
        message = "\n".join(lines)

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


@app.command(name="list")
async def list_accounts():
    """List the current chain account and unlinked keys from the config file."""

    config_file_path = Path(settings.CONFIG_FILE)
    active_account = load_main_configuration(config_file_path)

    unlinked_keys, _ = await list_unlinked_keys()

    table = Table(title="Chain Accounts", show_lines=True)
    table.add_column("Name", justify="left", style="cyan", no_wrap=True)
    table.add_column("Path", justify="left", style="green")
    table.add_column("Chain", justify="left", style="magenta", no_wrap=True)

    if active_account:
        table.add_row(
            active_account.path.stem, str(active_account.path), f"[bold green]{active_account.chain}[/bold green]"
        )
    else:
        console.print("[bold red]No active account found in the config file.[/bold red]")

    if unlinked_keys:
        for key_file in unlinked_keys:
            if key_file.stem != "default":
                table.add_row(key_file.stem, str(key_file), "-")

    console.print(table)


@app.command()
async def config(
    private_key_file: Optional[Path] = typer.Option(None, help="Path to the private key file"),
    chain_type: Optional[str] = typer.Option(None, help="Type of blockchain (ETH, SOL, etc.)"),
):
    """
    Async command to link private keys to a blockchain, interactively or non-interactively.
    """

    if private_key_file is None:
        unlinked_keys, _ = await list_unlinked_keys()
        unlinked_keys = list(filter(lambda key_file: key_file.stem != "default", unlinked_keys))

        if not unlinked_keys:
            typer.secho("No unlinked private keys found.", fg=typer.colors.GREEN)
            raise typer.Exit()

        console.print("[bold cyan]Available unlinked private keys:[/bold cyan]")
        for idx, key in enumerate(unlinked_keys, start=1):
            console.print(f"[{idx}] {key}")

        key_choice = Prompt.ask("Choose a private key by index or filename")

        if key_choice.isdigit():
            key_index = int(key_choice) - 1
            if 0 <= key_index < len(unlinked_keys):
                private_key_file = unlinked_keys[key_index]
            else:
                typer.secho("Invalid key index selected.", fg=typer.colors.RED)
                raise typer.Exit()
        else:
            matching_keys = [key for key in unlinked_keys if key.name == key_choice]
            if matching_keys:
                private_key_file = matching_keys[0]
            else:
                typer.secho("No matching key found with the provided name.", fg=typer.colors.RED)
                raise typer.Exit()

    if chain_type is None:
        chain_type = Prompt.ask(
            "Which chain type do you want to link the key to?",
            choices=["ETH", "SOL", "AVAX", "BASE", "BSC"],
            default="ETH",
        )

    typer.secho(f"Private key file: {private_key_file}", fg=typer.colors.YELLOW)
    typer.secho(f"Chain type: {chain_type}", fg=typer.colors.YELLOW)

    new_account = MainConfiguration(path=private_key_file, chain=Chain(chain_type))

    try:
        save_main_configuration(settings.CONFIG_FILE, new_account)
        typer.secho(f"Key file {private_key_file} linked to {chain_type} successfully.", fg=typer.colors.GREEN)
    except ValueError as e:
        typer.secho(f"Error: {e}", fg=typer.colors.RED)


@app.command()
async def update(
    private_key_file: Optional[Path] = typer.Option(None, help="The new path to the private key file"),
    chain_type: Optional[str] = typer.Option(None, help="The new blockchain type (ETH, SOL, etc.)"),
):
    """
    Command to update an existing chain account.
    """

    try:
        existing_account = load_main_configuration(settings.CONFIG_FILE)

        if private_key_file:
            new_key_file = private_key_file
        elif existing_account and existing_account.path:
            new_key_file = existing_account.path
        else:
            typer.secho("No private key file or account path available", fg=typer.colors.RED)
            typer.Exit(1)

        if chain_type:
            new_chain_type = chain_type
        elif existing_account and existing_account.chain:
            new_chain_type = existing_account.chain
        else:
            typer.secho("No chain type available", fg=typer.colors.RED)
            typer.Exit(1)

        updated_account = MainConfiguration(path=new_key_file, chain=Chain(new_chain_type))

        save_main_configuration(settings.CONFIG_FILE, updated_account)

        typer.secho(
            f"Account {updated_account.path} Chain : {updated_account.chain} updated successfully!",
            fg=typer.colors.GREEN,
        )

    except ValueError as e:
        typer.secho(f"Error: {e}", fg=typer.colors.RED)
