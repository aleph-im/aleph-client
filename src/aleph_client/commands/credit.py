import logging
from pathlib import Path
from typing import Annotated, Optional

import typer
from aleph.sdk import AlephHttpClient
from aleph.sdk.account import _load_account
from aleph.sdk.conf import settings
from aleph.sdk.types import AccountFromPrivateKey
from aleph.sdk.utils import displayable_amount
from rich.console import Console
from rich.panel import Panel
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
                    Text.from_markup(f"Address: [bright_cyan]{address}[/bright_cyan]\n"),
                    Text("Credits:"),
                    Text.from_markup(f"[bright_cyan] {displayable_amount(credit.credits, decimals=2)}[/bright_cyan]"),
                ]
                console.print(
                    Panel(
                        Text.assemble(*infos),
                        title="Credits Infos",
                        border_style="bright_cyan",
                        expand=False,
                        title_align="left",
                    )
                )
    else:
        typer.echo("Error: Please provide either a private key, private key file, or an address.")
