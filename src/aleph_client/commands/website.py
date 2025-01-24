from __future__ import annotations

import logging
import re
from base64 import b16decode, b32encode
from collections.abc import Mapping
from json import dumps
from pathlib import Path
from typing import Dict, List, Optional, cast
from zipfile import BadZipFile

import aiohttp
import typer
from aleph.sdk import AlephHttpClient, AuthenticatedAlephHttpClient
from aleph.sdk.account import _load_account
from aleph.sdk.client.vm_client import VmClient
from aleph.sdk.conf import settings
from aleph.sdk.exceptions import ForgottenMessageError, MessageNotFoundError
from aleph.sdk.query.filters import MessageFilter
from aleph.sdk.types import AccountFromPrivateKey, StorageEnum
from aleph.sdk.utils import safe_getattr
from aleph_message.models import Chain, MessageType, ProgramMessage, StoreMessage
from aleph_message.models.execution.program import ProgramContent
from aleph_message.models.item_hash import ItemHash
from aleph_message.status import MessageStatus
from click import echo
from rich import box, print
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from aleph_client.commands import help_strings
from aleph_client.commands.utils import (
    filter_only_valid_messages,
    get_or_prompt_environment_variables,
    get_or_prompt_volumes,
    input_multiline,
    setup_logging,
    str_to_datetime,
    validated_prompt,
    yes_no_input,
)
from aleph_client.utils import AsyncTyper, create_archive, sanitize_url

logger = logging.getLogger(__name__)
app = AsyncTyper(no_args_is_help=True)


@app.command()
async def create(
    path: Path = typer.Argument(..., help=help_strings.PROGRAM_PATH),
    name: Optional[str] = typer.Option(None, help="Name for your program"),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    print_message: bool = typer.Option(False),
    verbose: bool = True,
    debug: bool = False,
) -> Optional[str]:
    """Deploy a website on aleph.im"""

    setup_logging(debug)

    path = path.absolute()

    return None


@app.command()
async def update(
    path: Path = typer.Argument(..., help=help_strings.PROGRAM_PATH),
    name: str = typer.Argument(..., help="Item hash to update"),
    private_key: Optional[str] = settings.PRIVATE_KEY_STRING,
    private_key_file: Optional[Path] = settings.PRIVATE_KEY_FILE,
    print_message: bool = typer.Option(False),
    verbose: bool = True,
    debug: bool = False,
):
    """Update a website on aleph.im"""

    setup_logging(debug)

    path = path.absolute()


@app.command()
async def delete(
    name: str = typer.Argument(..., help="Item hash to update"),
    reason: str = typer.Option("User deletion", help="Reason for deleting the website"),
    private_key: Optional[str] = settings.PRIVATE_KEY_STRING,
    private_key_file: Optional[Path] = settings.PRIVATE_KEY_FILE,
    print_message: bool = typer.Option(False),
    verbose: bool = True,
    debug: bool = False,
):
    """Delete a website on aleph.im"""

    setup_logging(debug)

    account = _load_account(private_key, private_key_file)


@app.command(name="list")
async def list_websites(
    address: Optional[str] = typer.Option(None, help="Owner address of the websites"),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    json: bool = typer.Option(default=False, help="Print as json instead of rich table"),
    debug: bool = False,
):
    """List all websites associated to an account"""

    setup_logging(debug)

    if address is None:
        account = _load_account(private_key, private_key_file)
        address = account.get_address()

    async with AlephHttpClient(api_server=settings.API_HOST) as client:
        resp = None
        try:
            resp = await client.fetch_aggregates(address=address, keys=["websites", "domains"])
        except aiohttp.ClientConnectorError as e:
            echo(f"Unable to connect to API server (CCN)\nError: {e}")
        except aiohttp.ClientResponseError:
            pass
        if not resp:
            typer.echo(f"Address: {address}\n\nNo website found\n")
            raise typer.Exit(code=1)

        websites, linked_domains = {}, {}
        if "domains" in resp:
            found_domains: Dict[str, List[str]] = {}
            for domain, content in resp["domains"].items():
                if content and content["type"] == "ipfs":
                    version = content["message_id"]
                    found_domains[version] = found_domains.get(version, [])
                    found_domains[version].append(domain)
            linked_domains.update(found_domains)

        if "websites" in resp:
            found_websites: Dict[str, Dict] = {}
            for sitename, content in resp["websites"].items():
                if content:
                    found_websites[sitename] = content
                    current_version = content["volume_id"]
                    if current_version in linked_domains:
                        content["linked_domains"] = content.get("linked_domains", {})
                        content["linked_domains"]["current"] = linked_domains[current_version]
                    if "history" in content:
                        for version, volume_id in content["history"].items():
                            if volume_id in linked_domains:
                                domains = content["linked_domains"] = content.get("linked_domains", {})
                                legacy = domains["legacy"] = domains.get("legacy", {})
                                legacy[version] = legacy.get(version, [])
                                legacy[version].extend(linked_domains[volume_id])
            websites.update(found_websites)

        if not websites:
            typer.echo(f"Address: {address}\n\nNo website found\n")
            raise typer.Exit(code=1)
        if json:
            print(dumps(websites, indent=4))
        else:
            table = Table(box=box.ROUNDED, style="blue_violet")
            table.add_column(f"Websites [{len(websites)}]", style="blue", overflow="fold")
            table.add_column("Specifications", style="blue")
            table.add_column("Linked Domains", style="blue", overflow="fold")

            for sitename, details in websites.items():
                name = Text(sitename, style="magenta3")
                current_volume = details["volume_id"]
                msg_link = f"https://explorer.aleph.im/address/ETH/{address}/message/STORE/{current_volume}"
                item_hash_link = Text.from_markup(f"[link={msg_link}]{current_volume}[/link]", style="bright_cyan")
                created_at = Text.assemble(
                    "Created at: ",
                    Text(
                        str(str_to_datetime(str(details["created_at"]))).split(".", maxsplit=1)[0],
                        style="orchid",
                    ),
                )
                updated_at = Text.assemble(
                    "Updated at: ",
                    Text(
                        str(str_to_datetime(str(details["updated_at"]))).split(".", maxsplit=1)[0],
                        style="orchid",
                    ),
                )
                website = Text.assemble(
                    "Item Hash ↓\t     Name: ", name, "\n", item_hash_link, "\n", created_at, "  ", updated_at
                )
                specs = [
                    (
                        f"Framework: [magenta3]{details["metadata"]['framework']}[/magenta3]"
                        if "framework" in details["metadata"]
                        else ""
                    ),
                    f"Current Version: [magenta3]{details['version']}[/magenta3]",
                    f"History Size: [magenta3]{len(details.get('history', {}))}[/magenta3]",
                ]
                specifications = Text.from_markup("\n".join(specs))
                url = ""  # TODO: Calc v1 CID for default url
                domains = Text.from_markup(f"[bright_yellow][link={url}]{url}[/link][/bright_yellow]")
                table.add_row(website, specifications, domains)
                table.add_section()

            console = Console()
            console.print(table)
            infos = [
                Text.from_markup(
                    f"[bold]Address:[/bold] [bright_cyan]{address}[/bright_cyan]\n\nTo check all available commands, use:\n"
                ),
                Text.from_markup(
                    "↳ aleph website --help",
                    style="italic",
                ),
            ]
            console.print(
                Panel(
                    Text.assemble(*infos), title="Infos", border_style="bright_cyan", expand=False, title_align="left"
                )
            )


@app.command()
async def history(
    name: str = typer.Argument(..., help="Item hash to update"),
    restore: Optional[str] = None,
    prune: Optional[str] = None,
    private_key: Optional[str] = settings.PRIVATE_KEY_STRING,
    private_key_file: Optional[Path] = settings.PRIVATE_KEY_FILE,
    print_message: bool = typer.Option(False),
    verbose: bool = True,
    debug: bool = False,
):
    """List, prune, or revert to previous versions of a website"""

    setup_logging(debug)
