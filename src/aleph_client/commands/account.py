from __future__ import annotations

import asyncio
import base64
import logging
from enum import Enum
from pathlib import Path
from typing import Annotated, Optional

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
from aleph.sdk.evm_utils import (
    get_chains_with_holding,
    get_chains_with_super_token,
    get_compatible_chains,
)
from aleph.sdk.utils import bytes_from_hex, displayable_amount
from aleph_message.models import Chain
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text
from typer.colors import GREEN, RED

from aleph_client.commands import help_strings
from aleph_client.commands.help_strings import INVALID_KEY_FORMAT
from aleph_client.commands.utils import (
    input_multiline,
    setup_logging,
    validated_prompt,
    yes_no_input,
)
from aleph_client.utils import AsyncTyper, list_unlinked_keys

logger = logging.getLogger(__name__)
app = AsyncTyper(no_args_is_help=True)
console = Console()


class KeyEncoding(str, Enum):
    HEXADECIMAL = "hexadecimal"
    BASE32 = "base32"
    BASE64 = "base64"


def decode_private_key(private_key: str, encoding: KeyEncoding) -> bytes:
    """Decode a private key from a string via the specified encoding."""
    if encoding == KeyEncoding.HEXADECIMAL:
        return bytes_from_hex(private_key)
    elif encoding == KeyEncoding.BASE32:
        # Base32 keys are always uppercase
        return base64.b32decode(private_key.upper())
    elif encoding == KeyEncoding.BASE64:
        return base64.b64decode(private_key)
    else:
        raise ValueError(INVALID_KEY_FORMAT.format(encoding))


@app.command()
async def create(
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = None,
    private_key_file: Annotated[Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)] = None,
    chain: Annotated[Optional[Chain], typer.Option(help=help_strings.ORIGIN_CHAIN)] = None,
    replace: Annotated[bool, typer.Option(help=help_strings.CREATE_REPLACE)] = False,
    active: Annotated[bool, typer.Option(help=help_strings.CREATE_ACTIVE)] = True,
    debug: Annotated[bool, typer.Option()] = False,
    key_format: Annotated[KeyEncoding, typer.Option(help="Encoding of the private key")] = KeyEncoding.HEXADECIMAL,
):
    """Create or import a private key."""

    setup_logging(debug)

    # Prepares new private key file
    if not private_key_file:
        private_key_file = Path(
            validated_prompt("Enter a name or path for your private key", lambda path: len(path) > 0)
        )
    if not private_key_file.name.endswith(".key"):
        private_key_file = private_key_file.with_suffix(".key")
    if private_key_file.parent.as_posix() == ".":
        private_key_file = Path(settings.CONFIG_HOME or ".", "private-keys", private_key_file)
    if private_key_file.exists() and not replace:
        typer.secho(f"Error: private key file already exists: '{private_key_file}'", fg=RED)
        raise typer.Exit(1)

    # Prepares new private key
    private_key_bytes: bytes
    if private_key:
        if not chain:
            chain = Chain(
                Prompt.ask(
                    "Select the origin chain of your new private key: ",
                    choices=list(Chain),
                    default=Chain.ETH.value,
                )
            )
        if chain in (Chain.SOL, Chain.ECLIPSE):
            private_key_bytes = parse_solana_private_key(private_key)
        else:
            private_key_bytes = decode_private_key(private_key, key_format)
    else:
        private_key_bytes = generate_key()
    if not private_key_bytes:
        typer.secho("An unexpected error occurred!", fg=RED)
        raise typer.Exit(2)

    # Saves new private key
    private_key_file.parent.mkdir(parents=True, exist_ok=True)
    private_key_file.write_bytes(private_key_bytes)
    typer.secho(f"Private key stored in {private_key_file}", fg=GREEN)

    # Changes default configuration
    if active:
        if not chain:
            chain = Chain(
                Prompt.ask(
                    "Select the active chain: ",
                    choices=list(Chain),
                    default=Chain.ETH.value,
                )
            )

        try:
            new_config = MainConfiguration(path=private_key_file, chain=chain)
            save_main_configuration(settings.CONFIG_FILE, new_config)
            typer.secho(
                f"Private key {new_config.path} on chain {new_config.chain} is now your default configuration.",
                fg=GREEN,
            )
        except ValueError as e:
            typer.secho(f"Error: {e}", fg=typer.colors.RED)


@app.command(name="address")
def display_active_address(
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
):
    """
    Display your public address(es).
    """

    if private_key is not None:
        private_key_file = None
    elif private_key_file and not private_key_file.exists():
        typer.secho("No private key available", fg=RED)
        raise typer.Exit(code=1)

    evm_address = _load_account(private_key, private_key_file, chain=Chain.ETH).get_address()
    sol_address = _load_account(private_key, private_key_file, chain=Chain.SOL).get_address()

    console.print(
        "✉  [bold italic blue]Addresses for Active Account[/bold italic blue] ✉\n\n"
        f"[italic]EVM[/italic]: [cyan]{evm_address}[/cyan]\n"
        f"[italic]SOL[/italic]: [magenta]{sol_address}[/magenta]\n"
    )


@app.command(name="chain")
def display_active_chain():
    """
    Display the currently active chain.
    """

    config_file_path = Path(settings.CONFIG_FILE)
    config = load_main_configuration(config_file_path)
    active_chain = None
    if config and config.chain:
        active_chain = config.chain

    compatible_chains = get_compatible_chains()
    hold_chains = [*get_chains_with_holding(), Chain.SOL.value]
    payg_chains = get_chains_with_super_token()

    chain = f"[bold green]{active_chain}[/bold green]" if active_chain else "[red]Not Selected[/red]"
    active_chain_compatibility, compatibility = [], ""
    if active_chain in compatible_chains:
        active_chain_compatibility.append("SIGN")
    if active_chain in hold_chains:
        active_chain_compatibility.append("HOLD")
    if active_chain in payg_chains:
        active_chain_compatibility.append("PAYG")
    if active_chain_compatibility:
        compatibility = f"[magenta]{' / '.join(active_chain_compatibility)}[/magenta]"
    else:
        compatibility = "[red]Only Signing[/red]"

    console.print(f"[italic]Active Chain[/italic]: {chain}\t" + f"[italic]Compatibility[/italic]: {compatibility}")


@app.command(name="path")
def path_directory():
    """Display the directory path where your private keys, config file, and other settings are stored."""
    console.print(f"Aleph Home directory: [yellow]{settings.CONFIG_HOME}[/yellow]")


@app.command()
def show(
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
):
    """Display current configuration."""

    display_active_address(private_key=private_key, private_key_file=private_key_file)
    display_active_chain()


@app.command()
def export_private_key(
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = None,
    private_key_file: Annotated[Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)] = None,
):
    """
    Display your private key.
    """

    if private_key:
        private_key_file = None
    elif private_key_file and not private_key_file.exists():
        typer.secho("No private key available", fg=RED)
        raise typer.Exit(code=1)

    evm_pk = _load_account(private_key, private_key_file, chain=Chain.ETH).export_private_key()
    sol_pk = _load_account(private_key, private_key_file, chain=Chain.SOL).export_private_key()

    console.print(
        "⚠️  [bold italic red]Private Keys for Active Account[/bold italic red] ⚠️\n\n"
        f"[italic]EVM[/italic]: [cyan]{evm_pk}[/cyan]\n"
        f"[italic]SOL[/italic]: [magenta]{sol_pk}[/magenta]\n\n"
        "[bold italic red]Note: Aleph.im team will NEVER ask for them.[/bold italic red]"
    )


@app.command("sign-bytes")
def sign_bytes(
    message: Annotated[Optional[str], typer.Option(help="Message to sign")] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    chain: Annotated[Optional[Chain], typer.Option(help=help_strings.ADDRESS_CHAIN)] = None,
    debug: Annotated[bool, typer.Option()] = False,
):
    """Sign a message using your private key."""

    setup_logging(debug)

    account = _load_account(private_key, private_key_file, chain=chain)

    if not message:
        message = input_multiline()

    assert message is not None  # to please mypy
    coroutine = account.sign_raw(str(message).encode())
    signature = asyncio.run(coroutine)
    typer.echo("\nSignature: " + f"0x{signature.hex()}")


async def get_balance(address: str) -> dict:
    balance_data: dict = {}
    uri = f"{settings.API_HOST}/api/v0/addresses/{address}/balance"
    async with aiohttp.ClientSession() as session:
        response = await session.get(uri)
        if response.status == 200:
            balance_data = await response.json()
            balance_data["available_amount"] = balance_data["balance"] - balance_data["locked_amount"]
        else:
            error = f"Failed to retrieve balance for address {address}. Status code: {response.status}"
            raise Exception(error)
    return balance_data


@app.command()
async def balance(
    address: Annotated[Optional[str], typer.Option(help="Address")] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    chain: Annotated[Optional[Chain], typer.Option(help=help_strings.ADDRESS_CHAIN)] = None,
):
    """Display your ALEPH balance."""
    account = _load_account(private_key, private_key_file, chain=chain)

    if account and not address:
        address = account.get_address()

    if address:
        try:
            balance_data = await get_balance(address)
            infos = [
                Text.from_markup(f"Address: [bright_cyan]{balance_data['address']}[/bright_cyan]"),
                Text.from_markup(
                    f"\nBalance: [bright_cyan]{displayable_amount(balance_data['balance'], decimals=2)}[/bright_cyan]"
                ),
            ]
            details = balance_data.get("details")
            if details:
                infos += [Text("\n ↳ Details")]
                for chain_, chain_balance in details.items():
                    infos += [
                        Text.from_markup(
                            f"\n    {chain_}: [orange3]{displayable_amount(chain_balance, decimals=2)}[/orange3]"
                        )
                    ]
            available_color = "bright_cyan" if balance_data["available_amount"] >= 0 else "red"
            infos += [
                Text.from_markup(
                    f"\n - Locked: [bright_cyan]{displayable_amount(balance_data['locked_amount'], decimals=2)}"
                    "[/bright_cyan]"
                ),
                Text.from_markup(
                    f"\n - Available: [{available_color}]"
                    f"{displayable_amount(balance_data['available_amount'], decimals=2)}"
                    f"[/{available_color}]"
                ),
            ]
            console.print(
                Panel(
                    Text.assemble(*infos),
                    title="Account Infos",
                    border_style="bright_cyan",
                    expand=False,
                    title_align="left",
                )
            )
        except Exception as e:
            typer.echo(e)
    else:
        typer.echo("Error: Please provide either a private key, private key file, or an address.")


@app.command(name="list")
async def list_accounts():
    """Display available private keys, along with currenlty active chain and account (from config file)."""

    config_file_path = Path(settings.CONFIG_FILE)
    config = load_main_configuration(config_file_path)
    unlinked_keys, _ = await list_unlinked_keys()

    table = Table(title="\n🔑  Found Private Keys 🔑", title_justify="left", show_lines=True)
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Path", style="green")
    table.add_column("Active", no_wrap=True)

    active_chain = None
    if config:
        active_chain = config.chain
        table.add_row(config.path.stem, str(config.path), "[bold green]*[/bold green]")
    else:
        console.print(
            "[red]No private key path selected in the config file.[/red]\nTo set it up, use: [bold "
            "italic cyan]aleph account config[/bold italic cyan]\n"
        )

    if unlinked_keys:
        for key_file in unlinked_keys:
            if key_file.stem != "default":
                table.add_row(key_file.stem, str(key_file), "[bold red]-[/bold red]")

    hold_chains = [*get_chains_with_holding(), Chain.SOL.value]
    payg_chains = get_chains_with_super_token()

    active_address = None
    if config and config.path and active_chain:
        account = _load_account(private_key_path=config.path, chain=active_chain)
        active_address = account.get_address()

    console.print(
        "🌐  [bold italic blue]Chain Infos[/bold italic blue] 🌐\n"
        f"[italic]Chains with Signing[/italic]: [blue]{', '.join(list(Chain))}[/blue]\n"
        f"[italic]Chains with Hold-tier[/italic]: [blue]{', '.join(hold_chains)}[/blue]\n"
        f"[italic]Chains with Pay-As-You-Go[/italic]: [blue]{', '.join(payg_chains)}[/blue]\n\n"
        "🗃️  [bold italic green]Current Configuration[/bold italic green] 🗃️\n"
        + (f"[italic]Active Address[/italic]: [bright_cyan]{active_address}[/bright_cyan]" if active_address else "")
    )
    display_active_chain()
    console.print(table)


@app.command(name="config")
async def configure(
    private_key_file: Annotated[Optional[Path], typer.Option(help="New path to the private key file")] = None,
    chain: Annotated[Optional[Chain], typer.Option(help="New active chain")] = None,
):
    """Configure current private key file and active chain (default selection)"""

    unlinked_keys, config = await list_unlinked_keys()

    # Fixes private key file path
    if private_key_file:
        if not private_key_file.name.endswith(".key"):
            private_key_file = private_key_file.with_suffix(".key")
        if private_key_file.parent.as_posix() == ".":
            private_key_file = Path(settings.CONFIG_HOME or ".", "private-keys", private_key_file)

    # Checks if private key file exists
    if private_key_file and not private_key_file.exists():
        typer.secho(f"Private key file not found: {private_key_file}", fg=typer.colors.RED)
        raise typer.Exit()

    # Configures active private key file
    if not private_key_file and config and hasattr(config, "path") and Path(config.path).exists():
        if not yes_no_input(
            f"Active private key file: [bright_cyan]{config.path}[/bright_cyan]\n[yellow]Keep current active private "
            "key?[/yellow]",
            default="y",
        ):
            unlinked_keys = list(filter(lambda key_file: key_file.stem != "default", unlinked_keys))
            if not unlinked_keys:
                typer.secho("No unlinked private keys found.", fg=typer.colors.GREEN)
                raise typer.Exit()

            console.print("[bold cyan]Available unlinked private keys:[/bold cyan]")
            for idx, key in enumerate(unlinked_keys, start=1):
                console.print(f"[{idx}] {key}")

            key_choice = Prompt.ask("Choose a private key by index")
            if key_choice.isdigit():
                key_index = int(key_choice) - 1
                if 0 <= key_index < len(unlinked_keys):
                    private_key_file = unlinked_keys[key_index]
            if not private_key_file:
                typer.secho("Invalid file index.", fg=typer.colors.RED)
                raise typer.Exit()
        else:  # No change
            private_key_file = Path(config.path)

    if not private_key_file:
        typer.secho("No private key file provided or found.", fg=typer.colors.RED)
        raise typer.Exit()

    # Configure active chain
    if not chain and config and hasattr(config, "chain"):
        if not yes_no_input(
            f"Active chain: [bright_cyan]{config.chain}[/bright_cyan]\n[yellow]Keep current active chain?[/yellow]",
            default="y",
        ):
            chain = Chain(
                Prompt.ask(
                    "Select the active chain: ",
                    choices=list(Chain),
                    default=Chain.ETH.value,
                )
            )
        else:  # No change
            chain = Chain(config.chain)

    if not chain:
        typer.secho("No chain provided.", fg=typer.colors.RED)
        raise typer.Exit()

    try:
        config = MainConfiguration(path=private_key_file, chain=chain)
        save_main_configuration(settings.CONFIG_FILE, config)
        console.print(
            f"New Default Configuration: [italic bright_cyan]{config.path}[/italic bright_cyan] with [italic "
            f"bright_cyan]{config.chain}[/italic bright_cyan]",
            style=typer.colors.GREEN,
        )
    except ValueError as e:
        typer.secho(f"Error: {e}", fg=typer.colors.RED)
        raise typer.Exit(1) from e
