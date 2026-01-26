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
from aleph.sdk.client import AlephHttpClient
from aleph.sdk.conf import (
    AccountType,
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
from aleph.sdk.types import AccountFromPrivateKey
from aleph.sdk.utils import bytes_from_hex, displayable_amount
from aleph.sdk.wallets.ledger import LedgerETHAccount
from aleph_message.models import Chain
from ledgereth.exceptions import LedgerError
from rich import box
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
    validate_non_interactive_args_config,
    validated_prompt,
    yes_no_input,
)
from aleph_client.utils import (
    AsyncTyper,
    get_account_and_address,
    get_first_ledger_name,
    list_unlinked_keys,
    load_account,
    wait_for_ledger_connection,
)

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
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = None,
    private_key_file: Annotated[Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)] = None,
):
    """
    Display your public address(es).
    """

    config_file_path = Path(settings.CONFIG_FILE)
    config = load_main_configuration(config_file_path)
    account_type = config.type if config else None

    if not account_type or account_type == AccountType.IMPORTED:
        evm_address = load_account(private_key, private_key_file, chain=Chain.ETH).get_address()
        sol_address = load_account(private_key, private_key_file, chain=Chain.SOL).get_address()
    else:
        evm_address = config.address if config else "Not available"
        sol_address = "Not available (using Ledger device)"

    account_type_str = " (Ledger)" if account_type == AccountType.HARDWARE else ""
    console.print(
        f"✉  [bold italic blue]Addresses for Active Account{account_type_str}[/bold italic blue] ✉\n\n"
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
    # Check if we're using a Ledger account
    config_file_path = Path(settings.CONFIG_FILE)
    config = load_main_configuration(config_file_path)

    if config and config.type == AccountType.HARDWARE:
        typer.secho("Cannot export private key from a Ledger hardware wallet", fg=RED)
        typer.secho("The private key remains securely stored on your Ledger device", fg=RED)
        raise typer.Exit(code=1)

    # Normal private key handling
    if private_key:
        private_key_file = None
    elif private_key_file and not private_key_file.exists():
        typer.secho("No private key available", fg=RED)
        raise typer.Exit(code=1)

    eth_account = _load_account(private_key, private_key_file, chain=Chain.ETH)
    sol_account = _load_account(private_key, private_key_file, chain=Chain.SOL)

    evm_pk = "Not Available"
    if isinstance(eth_account, AccountFromPrivateKey):
        evm_pk = eth_account.export_private_key()
    sol_pk = "Not Available"
    if isinstance(sol_account, AccountFromPrivateKey):
        sol_pk = sol_account.export_private_key()
    console.print(
        "⚠️  [bold italic red]Private Keys for Active Account[/bold italic red] ⚠️\n\n"
        f"[italic]EVM[/italic]: [cyan]{evm_pk}[/cyan]\n"
        f"[italic]SOL[/italic]: [magenta]{sol_pk}[/magenta]\n\n"
        "[bold italic red]Note: Aleph Cloud team will NEVER ask for them.[/bold italic red]"
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

    account = load_account(private_key, private_key_file, chain=chain)

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
    """Display your ALEPH balance and basic voucher information."""
    account, address = get_account_and_address(
        private_key=private_key, private_key_file=private_key_file, chain=chain, address=address
    )

    if address:
        try:
            async with AlephHttpClient(settings.API_HOST) as client:
                balance_data = await client.get_balances(address)
                available = balance_data.balance - balance_data.locked_amount
            infos = [
                Text.from_markup(f"Address: [bright_cyan]{balance_data.address}[/bright_cyan]"),
                Text.from_markup(
                    f"\nBalance: [bright_cyan]{displayable_amount(balance_data.balance, decimals=2)}[/bright_cyan]"
                ),
            ]
            details = balance_data.details
            if details:
                infos += [Text("\n ↳ Details")]
                for chain_, chain_balance in details.items():
                    infos += [
                        Text.from_markup(
                            f"\n    {chain_}: [orange3]{displayable_amount(chain_balance, decimals=2)}[/orange3]"
                        )
                    ]
            available_color = "bright_cyan" if available >= 0 else "red"
            infos += [
                Text.from_markup(
                    f"\n - Locked: [bright_cyan]{displayable_amount(balance_data.locked_amount, decimals=2)}"
                    "[/bright_cyan]"
                ),
                Text.from_markup(
                    f"\n - Available: [{available_color}]"
                    f"{displayable_amount(available, decimals=2)}"
                    f"[/{available_color}]"
                ),
            ]

            infos += [
                Text("\nCredits:"),
                Text.from_markup(
                    f"[bright_cyan] {displayable_amount(balance_data.credit_balance, decimals=2)}[/bright_cyan]"
                ),
            ]

            # Get vouchers and add them to Account Info panel
            async with AlephHttpClient(api_server=settings.API_HOST) as client:
                vouchers = await client.voucher.get_vouchers(address=address)
            if vouchers:
                voucher_names = [voucher.name for voucher in vouchers]
                infos += [
                    Text("\nVouchers:"),
                    Text.from_markup(f"\n [bright_cyan]{', '.join(voucher_names)}[/bright_cyan]"),
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
async def list_accounts(
    ledger_count: Annotated[int, typer.Option(help="Number of ledger account you want to get (default: 5)")] = 5,
):
    """Display available private keys, along with currenlty active chain and account (from config file)."""

    config_file_path = Path(settings.CONFIG_FILE)
    config = load_main_configuration(config_file_path)
    unlinked_keys, _ = await list_unlinked_keys()

    table = Table(title="\n🔑  Found Private Keys 🔑", title_justify="left", show_lines=True)
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Address", style="cyan", no_wrap=True)
    table.add_column("Path", style="green")
    table.add_column("Active", no_wrap=True)

    active_chain = None
    if config and config.path and config.path != Path("None"):
        active_chain = config.chain
        acc_address = load_account(None, config.path, chain=active_chain).get_address()
        table.add_row(config.path.stem, str(acc_address), str(config.path), "[bold green]*[/bold green]")
    elif config and config.address and config.type == AccountType.HARDWARE:
        active_chain = config.chain

        ledger_connected = False
        try:
            ledger_accounts = LedgerETHAccount.get_accounts(count=ledger_count)
            if ledger_accounts:
                ledger_connected = True
        except Exception:
            ledger_connected = False

        # Only show the config entry if no Ledger is connected
        if not ledger_connected:
            table.add_row(f"Ledger ({config.address})", "External (Ledger)", "[bold green]*[/bold green]")
    else:
        console.print(
            "[red]No private key path selected in the config file.[/red]\nTo set it up, use: [bold "
            "italic cyan]aleph account config[/bold italic cyan]\n"
        )

    if unlinked_keys:
        for key_file in unlinked_keys:
            if key_file.stem != "default":
                acc_address = load_account(None, key_file, chain=active_chain).get_address()
                table.add_row(key_file.stem, str(acc_address), str(key_file), "[bold red]-[/bold red]")

    active_ledger_address = None
    if config and config.type == AccountType.HARDWARE and config.address:
        active_ledger_address = config.address.lower()

    try:
        ledger_accounts = LedgerETHAccount.get_accounts(count=ledger_count)
        if ledger_accounts:
            for idx, ledger_acc in enumerate(ledger_accounts):
                if not ledger_acc.address:
                    continue

                current_address = ledger_acc.address.lower()
                is_active = active_ledger_address and current_address == active_ledger_address
                status = "[bold green]*[/bold green]" if is_active else "[bold red]-[/bold red]"

                table.add_row(f"Ledger #{idx}", ledger_acc.address, status)

    except Exception:
        logger.debug("No ledger detected or error communicating with Ledger")

    hold_chains = [*get_chains_with_holding(), Chain.SOL.value]
    payg_chains = get_chains_with_super_token()

    active_address = None
    if config and active_chain:
        if config.path:
            account = _load_account(private_key_path=config.path, chain=active_chain)
            active_address = account.get_address()
        elif config.address and config.type == AccountType.HARDWARE:
            active_address = config.address

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


@app.command(name="vouchers")
async def vouchers(
    address: Annotated[Optional[str], typer.Option(help="Address")] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    chain: Annotated[Optional[Chain], typer.Option(help=help_strings.ADDRESS_CHAIN)] = None,
):
    """Display detailed information about your vouchers."""
    account, address = get_account_and_address(
        private_key=private_key, private_key_file=private_key_file, chain=chain, address=address
    )

    if address:
        try:
            async with AlephHttpClient(settings.API_HOST) as client:
                vouchers = await client.voucher.get_vouchers(address=address)
            if vouchers:
                voucher_table = Table(title="", show_header=True, box=box.ROUNDED)
                voucher_table.add_column("Name", style="bright_cyan")
                voucher_table.add_column("Description", style="green")
                voucher_table.add_column("Attributes", style="magenta")

                for voucher in vouchers:
                    attr_text = ""
                    for attr in voucher.attributes:
                        attr_text += f"{attr.trait_type}: {attr.value}\n"

                    voucher_table.add_row(voucher.name, voucher.description, attr_text.strip())

                console.print(
                    Panel(
                        voucher_table,
                        title="Vouchers",
                        border_style="bright_cyan",
                        expand=False,
                        title_align="left",
                    )
                )
            else:
                console.print(
                    Panel(
                        "No vouchers found for this address",
                        title="Vouchers",
                        border_style="bright_cyan",
                        expand=False,
                        title_align="left",
                    )
                )
        except Exception as e:
            typer.echo(e)
    else:
        typer.echo("Error: Please provide either a private key, private key file, or an address.")


@app.command(name="config")
async def configure(
    private_key_file: Annotated[Optional[Path], typer.Option(help="New path to the private key file")] = None,
    chain: Annotated[Optional[Chain], typer.Option(help="New active chain")] = None,
    address: Annotated[Optional[str], typer.Option(help="New active address")] = None,
    account_type: Annotated[Optional[AccountType], typer.Option(help="Account type")] = None,
    derivation_path: Annotated[
        Optional[str], typer.Option(help="Derivation path for ledger (e.g. \"44'/60'/0'/0/0\")")
    ] = None,
    ledger_count: Annotated[int, typer.Option(help="Number of ledger account you want to fetch (default: 5)")] = 5,
    non_it: Annotated[
        bool, typer.Option("--non-it", help="Non-interactive mode. Only apply provided options.")
    ] = False,
):
    """Configure current private key file and active chain (default selection)"""

    if settings.CONFIG_HOME:
        settings.CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        private_keys_dir = Path(settings.CONFIG_HOME, "private-keys")
        private_keys_dir.mkdir(parents=True, exist_ok=True)

    unlinked_keys, config = await list_unlinked_keys()

    if non_it:
        validate_non_interactive_args_config(config, account_type, private_key_file, address, chain, derivation_path)

        new_chain = chain or config.chain
        new_type = account_type or config.type
        new_address = address or config.address
        new_key = private_key_file or (Path(config.path) if hasattr(config, "path") else None)
        new_derivation_path = derivation_path or getattr(config, "derivation_path", None)

        config = MainConfiguration(
            path=new_key, chain=new_chain, address=new_address, type=new_type, derivation_path=new_derivation_path
        )
        save_main_configuration(settings.CONFIG_FILE, config)
        typer.secho("Configuration updated (non-interactive).", fg=typer.colors.GREEN)
        return

    current_device = f"{get_first_ledger_name()}" if config.type == AccountType.HARDWARE else f"File: {config.path}"
    current_derivation_path = getattr(config, "derivation_path", None)

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

    console.print(f"Current account type: [bright_cyan]{config.type}[/bright_cyan] - {current_device}")
    if current_derivation_path:
        console.print(f"Current derivation path: [bright_cyan]{current_derivation_path}[/bright_cyan]")

    if yes_no_input("Do you want to change the account type?", default="n"):
        account_type = AccountType(
            Prompt.ask("Select new account type", choices=list(AccountType), default=config.type)
        )
    else:
        account_type = config.type

    address = None
    if config.type == AccountType.IMPORTED:
        current_key = Path(config.path) if hasattr(config, "path") else None
        current_account = _load_account(private_key_str=None, private_key_path=current_key, chain=chain)
        address = current_account.get_address()
    else:
        address = config.address

    console.print(f"Current address: {address}")

    if account_type == AccountType.IMPORTED:
        # Determine if we need to ask about keeping or picking a key
        current_key = Path(config.path) if getattr(config, "path", None) else None

        if config.type == AccountType.IMPORTED:
            change_key = not yes_no_input("[yellow]Keep current private key?[/yellow]", default="y")
        else:
            console.print(
                "[yellow]Switching from a hardware account to an imported one.[/yellow]\n"
                "You need to select a private key file to use."
            )
            change_key = True

        # If user wants to change key or we must pick one
        if change_key:
            unlinked_keys = [k for k in unlinked_keys if k.stem != "default"]
            if not unlinked_keys:
                typer.secho("No unlinked private keys found.", fg=typer.colors.YELLOW)
                raise typer.Exit()

            console.print("[bold cyan]Available unlinked private keys:[/bold cyan]")
            for idx, key in enumerate(unlinked_keys, start=1):
                acc = _load_account(private_key_str=None, private_key_path=key, chain=chain)
                console.print(f"[{idx}] {key} - {acc.get_address()}")

            key_choice = Prompt.ask("Choose a private key by index")
            if key_choice.isdigit():
                idx = int(key_choice) - 1
                if 0 <= idx < len(unlinked_keys):
                    private_key_file = unlinked_keys[idx]
                else:
                    typer.secho("Invalid index.", fg=typer.colors.RED)
                    raise typer.Exit()
            else:
                typer.secho("Invalid input.", fg=typer.colors.RED)
                raise typer.Exit()
        else:
            private_key_file = current_key

        # Clear derivation path when switching to imported
        derivation_path = None

    if account_type == AccountType.HARDWARE:
        # Handle derivation path for hardware wallet
        if derivation_path:
            console.print(f"Using provided derivation path: [bright_cyan]{derivation_path}[/bright_cyan]")
        elif current_derivation_path and not yes_no_input(
            f"Current derivation path: [bright_cyan]{current_derivation_path}[/bright_cyan]\n"
            f"[yellow]Keep current derivation path?[/yellow]",
            default="y",
        ):
            derivation_path = Prompt.ask("Enter new derivation path", default="44'/60'/0'/0/0")
        elif not current_derivation_path:
            if yes_no_input("Do you want to specify a derivation path?", default="n"):
                derivation_path = Prompt.ask("Enter derivation path", default="44'/60'/0'/0/0")
            else:
                derivation_path = None
        else:
            derivation_path = current_derivation_path

        # If the current config is hardware, show its current address
        if config.type == AccountType.HARDWARE and not derivation_path:
            change_address = not yes_no_input("[yellow]Keep current Ledger address?[/yellow]", default="y")
        else:
            # Switching from imported → hardware, must choose an address
            console.print(
                "[yellow]Switching from an imported account to a hardware one.[/yellow]\n"
                "You'll need to select a Ledger address to use."
            )
            change_address = True

        if change_address:
            try:
                # Wait for ledger being UP before continue anythings
                wait_for_ledger_connection()

                if derivation_path:
                    console.print(f"Using derivation path: [bright_cyan]{derivation_path}[/bright_cyan]")
                    try:
                        ledger_account = LedgerETHAccount.from_path(derivation_path)
                        address = ledger_account.get_address()
                        console.print(f"Derived address: [bright_cyan]{address}[/bright_cyan]")
                    except Exception as e:
                        logger.warning(f"Error getting account from path: {e}")
                        raise typer.Exit(code=1) from e
                else:
                    # Normal flow - show available accounts and let user choose
                    accounts = LedgerETHAccount.get_accounts(count=ledger_count)
                    addresses = [acc.address for acc in accounts]

                    console.print(f"[bold cyan]Available addresses on {get_first_ledger_name()}:[/bold cyan]")
                    for idx, addr in enumerate(addresses, start=1):
                        console.print(f"[{idx}] {addr}")

                    key_choice = Prompt.ask("Choose an address by index")
                    if key_choice.isdigit():
                        key_index = int(key_choice) - 1
                        if 0 <= key_index < len(addresses):
                            address = addresses[key_index]
                        else:
                            typer.secho("Invalid address index.", fg=typer.colors.RED)
                            raise typer.Exit()
                    else:
                        typer.secho("Invalid input.", fg=typer.colors.RED)
                        raise typer.Exit()

            except LedgerError as e:
                logger.warning(f"Ledger Error: {getattr(e, 'message', str(e))}")
                typer.secho(
                    "Failed to communicate with Ledger device. Make sure it's unlocked with the Ethereum app open.",
                    fg=RED,
                )
                raise typer.Exit(code=1) from e
            except OSError as e:
                logger.warning(f"OS Error accessing Ledger: {e!s}")
                typer.secho(
                    "Please ensure Udev rules are set to use Ledger and you have proper USB permissions.", fg=RED
                )
                raise typer.Exit(code=1) from e
            except BaseException as e:
                logger.warning(f"Unexpected error with Ledger: {e!s}")
                typer.secho("An unexpected error occurred while communicating with the Ledger device.", fg=RED)
                typer.secho("Please ensure your device is connected and working correctly.", fg=RED)
                raise typer.Exit(code=1) from e
        else:
            address = config.address

    # If chain is specified via command line, prioritize it
    if chain:
        pass
    elif config and hasattr(config, "chain"):
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

    if not account_type:
        account_type = AccountType.IMPORTED

    try:
        config = MainConfiguration(
            path=private_key_file, chain=chain, address=address, type=account_type, derivation_path=derivation_path
        )
        save_main_configuration(settings.CONFIG_FILE, config)

        # Display appropriate configuration details based on account type
        if account_type == AccountType.HARDWARE:
            config_details = f"{config.address}"
            if derivation_path:
                config_details += f" (derivation path: {derivation_path})"
        else:
            config_details = f"{config.path}"

        console.print(
            f"New Default Configuration: [italic bright_cyan]{config_details}"
            f"[/italic bright_cyan] with [italic bright_cyan]{config.chain}[/italic bright_cyan]",
            style=typer.colors.GREEN,
        )
    except ValueError as e:
        typer.secho(f"Error: {e}", fg=typer.colors.RED)
        raise typer.Exit(1) from e
