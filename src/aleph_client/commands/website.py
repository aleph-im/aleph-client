from __future__ import annotations

import logging
from json import dumps
from pathlib import Path
from typing import Annotated, Optional

import aiohttp
import typer
from aleph.sdk import AlephHttpClient
from aleph.sdk.account import _load_account
from aleph.sdk.conf import settings
from click import echo
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from aleph_client.commands import help_strings
from aleph_client.commands.files import download
from aleph_client.commands.utils import (
    ipfs_cid_v0_to_v1,
    setup_logging,
    str_to_datetime,
)
from aleph_client.utils import AsyncTyper

logger = logging.getLogger(__name__)
app = AsyncTyper(no_args_is_help=True)


@app.command()
async def create(
    name: Annotated[str, typer.Argument(help=help_strings.WEBSITE_NAME)],
    path: Annotated[Path, typer.Argument(help=help_strings.WEBSITE_PATH)],
    cid: Annotated[Optional[str], typer.Option(help=help_strings.WEBSITE_CID)] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    print_messages: Annotated[bool, typer.Option()] = False,
    verbose: Annotated[bool, typer.Option()] = True,
    debug: Annotated[bool, typer.Option()] = False,
) -> Optional[str]:
    """Deploy a website on aleph.im"""

    setup_logging(debug)

    path = path.absolute()

    # TODO: If already exists, prompt to redirect to update()
    # TODO: replace space by -

    return None


@app.command()
async def update(
    name: Annotated[str, typer.Argument(help=help_strings.WEBSITE_NAME)],
    path: Annotated[Path, typer.Argument(help=help_strings.WEBSITE_PATH)],
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    print_message: Annotated[bool, typer.Option()] = False,
    verbose: Annotated[bool, typer.Option()] = True,
    debug: Annotated[bool, typer.Option()] = False,
):
    """Update a website on aleph.im"""

    setup_logging(debug)

    # path = path.absolute()


@app.command()
async def delete(
    name: Annotated[str, typer.Argument(help="Item hash to update")],
    reason: Annotated[str, typer.Option(help="Reason for deleting the website")] = "User deletion",
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    print_message: Annotated[bool, typer.Option()] = False,
    verbose: Annotated[bool, typer.Option()] = True,
    debug: Annotated[bool, typer.Option()] = False,
):
    """Delete a website on aleph.im"""

    setup_logging(debug)

    # account = _load_account(private_key, private_key_file)


@app.command(name="list")
async def list_websites(
    address: Annotated[Optional[str], typer.Option(help="Owner address of the websites")] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    json: Annotated[bool, typer.Option(help="Print as json instead of rich table")] = False,
    debug: Annotated[bool, typer.Option()] = False,
):
    """list all websites associated to an account"""

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
            found_domains: dict[str, list[str]] = {}
            for domain, content in resp["domains"].items():
                if content and content["type"] == "ipfs":
                    version = content["message_id"]
                    found_domains[version] = found_domains.get(version, [])
                    found_domains[version].append(domain)
            linked_domains.update(found_domains)

        if "websites" in resp:
            found_websites: dict[str, dict] = {}
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
            echo(dumps(websites, indent=4))
        else:
            table = Table(box=box.ROUNDED, style="blue_violet")
            table.add_column(f"Websites [{len(websites)}]", style="blue", overflow="fold")
            table.add_column("Specifications", style="blue")
            table.add_column("Infos & Domains", style="blue", overflow="fold")

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
                    "Item Hash ↓\t     Name: ",
                    name,
                    "\n",
                    item_hash_link,
                    "\n",
                    created_at,
                    "  ",
                    updated_at,
                )
                specs = [
                    (
                        f"Framework: [magenta3]{details['metadata']['framework'].capitalize()}[/magenta3]"
                        if "framework" in details["metadata"]
                        else ""
                    ),
                    f"Current Version: [green]v{details['version']}[/green]",
                    f"History Size: [orange1]{len(details.get('history', {}))}[/orange1]",
                ]
                specifications = Text.from_markup("\n".join(specs))

                stored_msg_info = await download(current_volume, only_info=True, verbose=False)
                cid_v0 = stored_msg_info.hash
                displayed_cid = f"[bright_cyan]{cid_v0}[/bright_cyan]" if cid_v0 else "[orange1]Missing[/orange1]"
                cid_v1 = ipfs_cid_v0_to_v1(cid_v0) if cid_v0 else ""
                url = f"https://{cid_v1}.ipfs.aleph.sh"
                displayed_url = (
                    f"[bright_yellow][link={url}]{url}[/link][/bright_yellow]"
                    if cid_v1
                    else "[orange1]Missing[/orange1]"
                )
                current_domains, legacy_domains = "", ""
                if "linked_domains" in details:
                    if "current" in details["linked_domains"]:
                        for domain in details["linked_domains"]["current"]:
                            full_domain = f"https://{domain}"
                            current_domains += (
                                f"\n• [bright_cyan][link={full_domain}]{full_domain}[/link][/bright_cyan]"
                            )
                    if "legacy" in details["linked_domains"]:
                        legacy = sorted(
                            details["linked_domains"]["legacy"].items(), key=lambda x: int(x[0]), reverse=True
                        )
                        for version, urls in legacy:
                            legacy_urls = []
                            for domain in urls:
                                full_domain = f"https://{domain}"
                                legacy_urls.append(f"[cyan][link={full_domain}]{full_domain}[/link][/cyan]")
                            legacy_domains += f"\n• [orange1]v{version}[/orange1]: " + ", ".join(legacy_urls)
                domains = Text.assemble(
                    Text.from_markup(f"CID v0: {displayed_cid}\n"),
                    Text.from_markup(f"Default Gateway (using CID v1):\n↳ {displayed_url}\n"),
                    Text.from_markup(f"Custom Domains: {current_domains if current_domains else '-'}"),
                    Text.from_markup(f"\nLegacy Domains: {legacy_domains}") if legacy_domains else "",
                )
                table.add_row(website, specifications, domains)
                table.add_section()

            console = Console()
            console.print(table)
            infos = [
                Text.from_markup(
                    f"[bold]Address:[/bold] [bright_cyan]{address}[/bright_cyan]"
                    "\n\nTo check all available commands, use:\n"
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
    name: Annotated[str, typer.Argument(help="Item hash to update")],
    restore: Annotated[Optional[str], typer.Option()] = None,
    prune: Annotated[Optional[str], typer.Option()] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    print_message: Annotated[bool, typer.Option()] = False,
    verbose: Annotated[bool, typer.Option()] = True,
    debug: Annotated[bool, typer.Option()] = False,
):
    """list, prune, or restore previous versions of a website"""

    setup_logging(debug)
