import logging
from pathlib import Path
from typing import Annotated, Optional

import typer
from aiohttp import ClientResponseError
from aleph.sdk import AlephHttpClient
from aleph.sdk.account import _load_account
from aleph.sdk.conf import settings
from aleph.sdk.types import AccountFromPrivateKey
from aleph.sdk.utils import displayable_amount
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from aleph_client.commands import help_strings
from aleph_client.commands.utils import setup_logging
from aleph_client.utils import AsyncTyper

logger = logging.getLogger(__name__)
app = AsyncTyper(no_args_is_help=True)
console = Console()


@app.command()
async def show(
    address: Annotated[
        str,
        typer.Argument(help="Address of the wallet you want to check / None if you want check your current accounts"),
    ] = "",
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    json: Annotated[bool, typer.Option(help="Display as json")] = False,
    debug: Annotated[bool, typer.Option()] = False,
):
    """Display the numbers of credits for a specific address."""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    if account and not address:
        address = account.get_address()

    if address:
        async with AlephHttpClient(api_server=settings.API_HOST) as client:
            credit = await client.get_credit_balance(address=address)
            if json:
                typer.echo(credit.model_dump_json(indent=4))
            else:
                infos = [
                    Text.from_markup(f"Address: {address}\n"),
                    Text("Credits:"),
                    Text.from_markup(f" {displayable_amount(credit.credits, decimals=2)}"),
                ]
                console.print(
                    Panel(
                        Text.assemble(*infos),
                        title="Credits Infos",
                        border_style="blue",
                        expand=False,
                        title_align="left",
                    )
                )
    else:
        typer.echo("Error: Please provide either a private key, private key file, or an address.")


@app.command(name="history")
async def history(
    address: Annotated[
        str,
        typer.Argument(help="Address of the wallet you want to check / None if you want check your current accounts"),
    ] = "",
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    page_size: Annotated[int, typer.Option(help="Numbers of element per page")] = 100,
    page: Annotated[int, typer.Option(help="Current Page")] = 1,
    json: Annotated[bool, typer.Option(help="Display as json")] = False,
    debug: Annotated[bool, typer.Option()] = False,
):
    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    if account and not address:
        address = account.get_address()

    try:
        # Comment the original API call for testing
        async with AlephHttpClient(api_server=settings.API_HOST) as client:
            filtered_credits = await client.get_credit_history(address=address, page_size=page_size, page=page)
            if json:
                typer.echo(filtered_credits.model_dump_json(indent=4))
            else:
                table = Table(title="Credits History", border_style="blue", box=box.ROUNDED)
                table.add_column("Timestamp")
                table.add_column("Amount", justify="right")
                table.add_column("Payment Method")
                table.add_column("Origin")
                table.add_column("Origin Ref")
                table.add_column("Expiration Date")

                for credit in filtered_credits.credit_balances:
                    timestamp = Text(credit.message_timestamp.strftime("%Y-%m-%d %H:%M:%S"))
                    amount = Text(displayable_amount(credit.amount, decimals=2), style="cyan")
                    payment_method = Text(credit.payment_method if credit.payment_method else "-")
                    origin = Text(credit.origin if credit.origin else "-")
                    origin_ref = Text(credit.origin_ref if credit.origin_ref else "-")
                    expiration = Text(
                        credit.expiration_date.strftime("%Y-%m-%d") if credit.expiration_date else "Never",
                        style="red" if credit.expiration_date else "green",
                    )

                    table.add_row(timestamp, amount, payment_method, origin, origin_ref, expiration)

                # Add pagination footer
                pagination_info = Text.assemble(
                    "Page: ",
                    Text(f"{filtered_credits.pagination_page}", style="cyan"),
                    f" of {filtered_credits.pagination_total} | ",
                    "Items per page: ",
                    Text(f"{filtered_credits.pagination_per_page}"),
                    " | ",
                    "Total items: ",
                    Text(f"{filtered_credits.pagination_total}"),
                )
                table.caption = pagination_info

                console.print(table)

                # Add summary panel
                infos = [
                    Text.from_markup(f"[bold]Address:[/bold] {address}"),
                ]
                console.print(
                    Panel(
                        Text.assemble(*infos),
                        title="Credits Info",
                        border_style="blue",
                        expand=False,
                        title_align="left",
                    )
                )
    except ClientResponseError as e:
        typer.echo("Failed to retrieve credits history.")
        raise (e)
