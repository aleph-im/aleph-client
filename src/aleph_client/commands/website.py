from __future__ import annotations

import json as json_lib
import logging
import re
import time
from pathlib import Path
from typing import Annotated, Any, Optional
from urllib.parse import urlparse

import aiohttp
import typer
from aleph.sdk import AlephHttpClient, AuthenticatedAlephHttpClient
from aleph.sdk.conf import settings
from aleph.sdk.types import StorageEnum
from aleph_message.models import Chain
from aleph_message.status import MessageStatus
from rich import box
from rich.console import Console
from rich.table import Table

from aleph_client.commands import help_strings
from aleph_client.commands.utils import setup_logging
from aleph_client.utils import AsyncTyper, load_account

logger = logging.getLogger(__name__)
app = AsyncTyper(no_args_is_help=True)

IPFS_GATEWAY_URL = "https://ipfs.aleph.cloud/ipfs/"


def _sanitize_name(name: str) -> str:
    """Sanitize a website name: lowercase, replace spaces/special chars with dashes."""
    name = name.strip().lower()
    name = re.sub(r"[^a-z0-9-]", "-", name)
    name = re.sub(r"-+", "-", name)
    return name.strip("-")


async def _fetch_websites_aggregate(
    client: AlephHttpClient,
    address: str,
) -> dict[str, Any]:
    """Fetch the 'websites' aggregate for the given address."""
    try:
        aggregates = await client.fetch_aggregates(address=address, keys=["websites"])
    except Exception:
        return {}
    return aggregates.get("websites", {})


async def _fetch_domains_aggregate(
    client: AlephHttpClient,
    address: str,
) -> dict[str, Any]:
    """Fetch the 'domains' aggregate for the given address."""
    try:
        aggregates = await client.fetch_aggregates(address=address, keys=["domains"])
    except Exception:
        return {}
    return aggregates.get("domains", {})


async def _upload_directory(directory: Path) -> Optional[str]:
    """Upload a directory to IPFS and return the CID v0."""
    params = {"recursive": "true", "wrap-with-directory": "true"}

    files = {}
    for file_path in directory.rglob("*"):
        if file_path.is_file():
            relative_path = file_path.relative_to(directory)
            files[str(relative_path)] = open(file_path, "rb")

    try:
        url = urlparse(settings.IPFS_GATEWAY)._replace(path="/api/v0/add").geturl()
        async with aiohttp.ClientSession() as session:
            response = await session.post(url, params=params, data=files)
            response.raise_for_status()

            cid_v0 = None
            data = await response.text()
            for line in data.strip().splitlines():
                entry = json_lib.loads(line)
                cid_v0 = entry.get("Hash")

            return cid_v0
    finally:
        for f in files.values():
            f.close()


def _get_domains_for_volume(
    domains: dict[str, Any],
    volume_id: str,
) -> list[str]:
    """Find custom domains pointing to a given volume_id."""
    matched = []
    for fqdn, info in domains.items():
        if info and isinstance(info, dict) and info.get("message_id") == volume_id:
            matched.append(fqdn)
    return matched


@app.command(name="list")
async def list_websites(
    address: Annotated[Optional[str], typer.Option(help=help_strings.TARGET_ADDRESS)] = None,
    json: Annotated[bool, typer.Option(help="Print as JSON instead of a rich table")] = False,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    chain: Annotated[Optional[Chain], typer.Option(help=help_strings.ADDRESS_CHAIN)] = None,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
):
    """List all websites for the current account."""

    setup_logging(debug)

    account = load_account(private_key_str=private_key, private_key_file=private_key_file, chain=chain)
    address = address or settings.ADDRESS_TO_USE or account.get_address()

    async with AlephHttpClient(api_server=settings.API_HOST) as client:
        websites = await _fetch_websites_aggregate(client, address)
        domains = await _fetch_domains_aggregate(client, address)

        if not websites:
            typer.echo("No websites found.")
            return

        if json:
            typer.echo(json_lib.dumps(websites, indent=4))
            return

        table = Table(
            title="Websites",
            box=box.SIMPLE_HEAVY,
        )
        table.add_column("Name", style="cyan", no_wrap=True)
        table.add_column("Volume ID", style="bright_blue", no_wrap=True)
        table.add_column("Version", style="green")
        table.add_column("Framework", style="magenta")
        table.add_column("Custom Domains", style="yellow")
        table.add_column("Updated", style="blue")

        for name, info in websites.items():
            if not info or not isinstance(info, dict):
                continue

            volume_id = str(info.get("volume_id", ""))
            version = str(info.get("version", "?"))
            metadata = info.get("metadata") or {}
            framework = str(metadata.get("framework", "unknown"))
            updated_at = str(info.get("updated_at", info.get("created_at", "")))
            site_domains = _get_domains_for_volume(domains, volume_id)
            domains_str = ", ".join(site_domains) if site_domains else "-"

            short_hash = f"{volume_id[:8]}...{volume_id[-8:]}" if len(volume_id) > 20 else volume_id

            table.add_row(name, short_hash, version, framework, domains_str, updated_at)

        console = Console()
        console.print(table)


@app.command()
async def deploy(
    name: Annotated[str, typer.Argument(help=help_strings.WEBSITE_NAME)],
    path: Annotated[Path, typer.Argument(help=help_strings.WEBSITE_PATH)],
    framework: Annotated[str, typer.Option(help=help_strings.WEBSITE_FRAMEWORK)] = "unknown",
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    chain: Annotated[Optional[Chain], typer.Option(help=help_strings.ADDRESS_CHAIN)] = None,
    channel: Annotated[Optional[str], typer.Option(help=help_strings.CHANNEL)] = settings.DEFAULT_CHANNEL,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
):
    """Deploy a static website to IPFS and register it on Aleph Cloud."""

    setup_logging(debug)

    if not path.is_dir():
        typer.echo(f"Error: '{path}' is not a directory.")
        raise typer.Exit(code=1)

    name = _sanitize_name(name)
    if not name:
        typer.echo("Error: Invalid website name after sanitization.")
        raise typer.Exit(code=1)

    account = load_account(private_key_str=private_key, private_key_file=private_key_file, chain=chain)
    address = account.get_address()

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        websites = await _fetch_websites_aggregate(client, address)

        if name in websites and websites[name]:
            typer.echo(f"Error: Website '{name}' already exists. Use 'aleph website update' to update it.")
            raise typer.Exit(code=1)

        typer.echo(f"Uploading directory '{path}' to IPFS...")
        cid = await _upload_directory(path)
        if not cid:
            typer.echo("Error: Failed to upload directory to IPFS.")
            raise typer.Exit(code=1)

        typer.echo(f"Pinning CID {cid} on Aleph Cloud...")
        result, status = await client.create_store(
            file_hash=cid,
            storage_engine=StorageEnum.ipfs,
            channel=channel,
        )
        volume_id = result.item_hash

        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        aggregate_content = {
            name: {
                "volume_id": volume_id,
                "version": 1,
                "created_at": now,
                "updated_at": now,
                "metadata": {"framework": framework},
                "history": {},
            }
        }

        await client.create_aggregate(
            key="websites",
            content=aggregate_content,
            channel=channel,
        )

        typer.echo(f"Website '{name}' deployed successfully!")
        typer.echo(f"  Volume ID: {volume_id}")
        typer.echo(f"  IPFS Gateway: {IPFS_GATEWAY_URL}{cid}")


@app.command()
async def update(
    name: Annotated[str, typer.Argument(help=help_strings.WEBSITE_NAME)],
    path: Annotated[Path, typer.Argument(help=help_strings.WEBSITE_PATH)],
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    chain: Annotated[Optional[Chain], typer.Option(help=help_strings.ADDRESS_CHAIN)] = None,
    channel: Annotated[Optional[str], typer.Option(help=help_strings.CHANNEL)] = settings.DEFAULT_CHANNEL,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
):
    """Update an existing website with new content."""

    setup_logging(debug)

    if not path.is_dir():
        typer.echo(f"Error: '{path}' is not a directory.")
        raise typer.Exit(code=1)

    account = load_account(private_key_str=private_key, private_key_file=private_key_file, chain=chain)
    address = account.get_address()

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        websites = await _fetch_websites_aggregate(client, address)

        if name not in websites or not websites[name]:
            typer.echo(f"Error: Website '{name}' not found. Use 'aleph website deploy' to create it.")
            raise typer.Exit(code=1)

        site = websites[name]
        old_volume_id = site["volume_id"]
        old_version = site.get("version", 1)
        history = dict(site.get("history", {}))

        typer.echo(f"Uploading directory '{path}' to IPFS...")
        cid = await _upload_directory(path)
        if not cid:
            typer.echo("Error: Failed to upload directory to IPFS.")
            raise typer.Exit(code=1)

        typer.echo(f"Pinning CID {cid} on Aleph Cloud...")
        result, status = await client.create_store(
            file_hash=cid,
            storage_engine=StorageEnum.ipfs,
            channel=channel,
        )
        new_volume_id = result.item_hash

        history[str(old_version)] = old_volume_id
        new_version = old_version + 1
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        aggregate_content = {
            name: {
                "volume_id": new_volume_id,
                "version": new_version,
                "created_at": site.get("created_at", now),
                "updated_at": now,
                "metadata": site.get("metadata", {"framework": "unknown"}),
                "history": history,
            }
        }

        await client.create_aggregate(
            key="websites",
            content=aggregate_content,
            channel=channel,
        )

        typer.echo(f"Website '{name}' updated to version {new_version}!")
        typer.echo(f"  Volume ID: {new_volume_id}")
        typer.echo(f"  IPFS Gateway: {IPFS_GATEWAY_URL}{cid}")


@app.command()
async def delete(
    name: Annotated[str, typer.Argument(help=help_strings.WEBSITE_NAME)],
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    chain: Annotated[Optional[Chain], typer.Option(help=help_strings.ADDRESS_CHAIN)] = None,
    channel: Annotated[Optional[str], typer.Option(help=help_strings.CHANNEL)] = settings.DEFAULT_CHANNEL,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
):
    """Delete a website from the registry."""

    setup_logging(debug)

    account = load_account(private_key_str=private_key, private_key_file=private_key_file, chain=chain)
    address = account.get_address()

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        websites = await _fetch_websites_aggregate(client, address)

        if name not in websites or not websites[name]:
            typer.echo(f"Error: Website '{name}' not found.")
            raise typer.Exit(code=1)

        aggregate_content = {name: None}

        await client.create_aggregate(
            key="websites",
            content=aggregate_content,
            channel=channel,
        )

        typer.echo(f"Website '{name}' deleted.")


@app.command()
async def history(
    name: Annotated[str, typer.Argument(help=help_strings.WEBSITE_NAME)],
    restore: Annotated[Optional[int], typer.Option(help="Version number to restore")] = None,
    prune: Annotated[bool, typer.Option(help="Remove all history, keep only current version")] = False,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    chain: Annotated[Optional[Chain], typer.Option(help=help_strings.ADDRESS_CHAIN)] = None,
    channel: Annotated[Optional[str], typer.Option(help=help_strings.CHANNEL)] = settings.DEFAULT_CHANNEL,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
):
    """View or manage version history of a website."""

    setup_logging(debug)

    account = load_account(private_key_str=private_key, private_key_file=private_key_file, chain=chain)
    address = account.get_address()

    if restore is not None or prune:
        async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
            websites = await _fetch_websites_aggregate(client, address)
            if name not in websites or not websites[name]:
                typer.echo(f"Error: Website '{name}' not found.")
                raise typer.Exit(code=1)

            site = websites[name]
            site_history = dict(site.get("history", {}))
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

            if restore is not None:
                version_key = str(restore)
                if version_key not in site_history:
                    typer.echo(f"Error: Version {restore} not found in history.")
                    raise typer.Exit(code=1)

                restored_volume_id = site_history[version_key]
                current_volume_id = site["volume_id"]
                current_version = site.get("version", 1)

                site_history[str(current_version)] = current_volume_id
                new_version = current_version + 1

                aggregate_content = {
                    name: {
                        "volume_id": restored_volume_id,
                        "version": new_version,
                        "created_at": site.get("created_at", now),
                        "updated_at": now,
                        "metadata": site.get("metadata", {"framework": "unknown"}),
                        "history": site_history,
                    }
                }

                await client.create_aggregate(
                    key="websites",
                    content=aggregate_content,
                    channel=channel,
                )

                typer.echo(f"Restored version {restore} as version {new_version}.")
                typer.echo(f"  Volume ID: {restored_volume_id}")

            elif prune:
                aggregate_content = {
                    name: {
                        "volume_id": site["volume_id"],
                        "version": site.get("version", 1),
                        "created_at": site.get("created_at", now),
                        "updated_at": now,
                        "metadata": site.get("metadata", {"framework": "unknown"}),
                        "history": {},
                    }
                }

                await client.create_aggregate(
                    key="websites",
                    content=aggregate_content,
                    channel=channel,
                )

                typer.echo(f"History pruned for '{name}'. Only current version retained.")

    else:
        async with AlephHttpClient(api_server=settings.API_HOST) as client:
            websites = await _fetch_websites_aggregate(client, address)
            if name not in websites or not websites[name]:
                typer.echo(f"Error: Website '{name}' not found.")
                raise typer.Exit(code=1)

            site = websites[name]
            site_history = site.get("history", {})

            table = Table(
                title=f"Version History: {name}",
                box=box.SIMPLE_HEAVY,
            )
            table.add_column("Version", style="green")
            table.add_column("Volume ID", style="bright_blue", no_wrap=True)
            table.add_column("Current", style="yellow")

            current_version = site.get("version", 1)
            current_volume_id = str(site.get("volume_id", ""))

            for ver, vol_id in sorted(site_history.items(), key=lambda x: int(x[0])):
                vol_id = str(vol_id)
                short_hash = f"{vol_id[:8]}...{vol_id[-8:]}" if len(vol_id) > 20 else vol_id
                table.add_row(str(ver), short_hash, "")

            short_current = (
                f"{current_volume_id[:8]}...{current_volume_id[-8:]}"
                if len(current_volume_id) > 20
                else current_volume_id
            )
            table.add_row(str(current_version), short_current, "*")

            console = Console()
            console.print(table)
