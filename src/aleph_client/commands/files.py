from __future__ import annotations

import json as json_lib
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import aiohttp
import typer
from aleph.sdk import AlephHttpClient, AuthenticatedAlephHttpClient
from aleph.sdk.account import _load_account
from aleph.sdk.conf import settings
from aleph.sdk.types import AccountFromPrivateKey, StorageEnum
from aleph_message.models import ItemHash, StoreMessage
from aleph_message.status import MessageStatus
from pydantic import BaseModel, Field
from rich import box
from rich.console import Console
from rich.table import Table

from aleph_client.commands import help_strings
from aleph_client.commands.utils import setup_logging
from aleph_client.utils import AsyncTyper

logger = logging.getLogger(__name__)
app = AsyncTyper(no_args_is_help=True)


@app.command()
async def pin(
    item_hash: str = typer.Argument(..., help="IPFS hash to pin on aleph.im"),
    channel: Optional[str] = typer.Option(default=settings.DEFAULT_CHANNEL, help=help_strings.CHANNEL),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    ref: Optional[str] = typer.Option(None, help=help_strings.REF),
    debug: bool = False,
):
    """Persist a file from IPFS on aleph.im."""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        result: StoreMessage
        status: MessageStatus
        result, status = await client.create_store(
            file_hash=item_hash,
            storage_engine=StorageEnum.ipfs,
            channel=channel,
            ref=ref,
        )
        logger.debug("Upload finished")
        typer.echo(f"{result.json(indent=4)}")


@app.command()
async def upload(
    path: Path = typer.Argument(..., help="Path of the file to upload"),
    channel: Optional[str] = typer.Option(default=settings.DEFAULT_CHANNEL, help=help_strings.CHANNEL),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    ref: Optional[str] = typer.Option(None, help=help_strings.REF),
    debug: bool = False,
):
    """Upload and store a file on aleph.im."""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        if not path.is_file():
            typer.echo(f"Error: File not found: '{path}'")
            raise typer.Exit(code=1)

        with open(path, "rb") as fd:
            logger.debug("Reading file")
            # TODO: Read in lazy mode instead of copying everything in memory
            file_content = fd.read()
            storage_engine = StorageEnum.ipfs if len(file_content) > 4 * 1024 * 1024 else StorageEnum.storage
            logger.debug("Uploading file")
            result: StoreMessage
            status: MessageStatus
            result, status = await client.create_store(
                file_content=file_content,
                storage_engine=storage_engine,
                channel=channel,
                guess_mime_type=True,
                ref=ref,
            )
            logger.debug("Upload finished")
            typer.echo(f"{result.json(indent=4)}")


@app.command()
async def download(
    hash: str = typer.Argument(..., help="hash to download from aleph."),
    use_ipfs: bool = typer.Option(default=False, help="Download using IPFS instead of storage"),
    output_path: Path = typer.Option(Path("."), help="Output directory path"),
    file_name: str = typer.Option(None, help="Output file name (without extension)"),
    file_extension: str = typer.Option(None, help="Output file extension"),
    debug: bool = False,
):
    """Download a file on aleph.im."""

    setup_logging(debug)

    output_path.mkdir(parents=True, exist_ok=True)

    file_name = file_name if file_name else hash
    file_extension = file_extension if file_extension else ""

    output_file_path = output_path / f"{file_name}{file_extension}"

    async with AlephHttpClient(api_server=settings.API_HOST) as client:
        logger.info(f"Downloading {hash} ...")
        with open(output_file_path, "wb") as fd:
            if not use_ipfs:
                await client.download_file_to_buffer(hash, fd)
            else:
                await client.download_file_ipfs_to_buffer(hash, fd)

        logger.debug("File downloaded successfully.")


@app.command()
async def forget(
    item_hash: str = typer.Argument(..., help="Hash to forget"),
    reason: str = typer.Argument("User deletion", help="reason to forget"),
    channel: Optional[str] = typer.Option(default=settings.DEFAULT_CHANNEL, help=help_strings.CHANNEL),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    """forget a file and his message on aleph.im."""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        value = await client.forget(hashes=[ItemHash(item_hash)], reason=reason, channel=channel)
        typer.echo(f"{value[0].json(indent=4)}")


class GetAccountFilesQueryParams(BaseModel):
    pagination: int = Field(
        default=100,
        ge=0,
        description="Maximum number of files to return. Specifying 0 removes this limit.",
    )
    page: int = Field(default=1, ge=1, description="Offset in pages. Starts at 1.")
    sort_order: int = Field(
        default=-1,
        description="Order in which files should be listed: -1 means most recent messages first, 1 means older messages first.",
    )


def _show_files(files_data: dict) -> None:
    table = Table(title="Files Information", box=box.SIMPLE_HEAVY)
    table.add_column("File Hash", style="cyan", no_wrap=True, min_width=None)
    table.add_column("Size (MB)", style="magenta", min_width=None)
    table.add_column("Type", style="green", min_width=None)
    table.add_column("Created", style="blue", min_width=None)
    table.add_column("Item Hash", style="yellow", min_width=None, no_wrap=True)

    console = Console()

    # Add files to the table
    for file_info in files_data["files"]:
        created = datetime.strptime(file_info["created"], "%Y-%m-%dT%H:%M:%S.%f%z")
        formatted_created = created.strftime("%Y-%m-%d %H:%M:%S")
        size_in_mb = float(file_info["size"]) / (1024 * 1024)
        table.add_row(
            file_info["file_hash"],
            f"{size_in_mb:.4f} MB",
            file_info["type"],
            formatted_created,
            file_info["item_hash"],
        )

    pagination_page = files_data["pagination_page"]
    pagination_total = files_data["pagination_total"]
    pagination_per_page = files_data["pagination_per_page"]
    address = files_data["address"]
    total_size = float(files_data["total_size"]) / (1024 * 1024)

    console.print(
        f"\n[bold]Address:[/bold] {address}",
    )
    console.print(f"[bold]Total Size:[/bold] ~ {total_size:.4f} MB")

    console.print("\n[bold]Pagination:[/bold]")
    console.print(
        f"[bold]Page:[/bold] {pagination_page}",
    )
    console.print(
        f"[bold]Total Item:[/bold] {pagination_total}",
    )
    console.print(f"[bold]Items Max Per Page:[/bold] {pagination_per_page}")

    console.print(table)


@app.command()
async def list(
    address: Optional[str] = typer.Option(None, help="Address"),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    pagination: int = typer.Option(100, help="Maximum number of files to return."),
    page: int = typer.Option(1, help="Offset in pages."),
    sort_order: int = typer.Option(
        -1,
        help="Order in which files should be listed: -1 means most recent messages first, 1 means older messages first.",
    ),
    json: bool = typer.Option(default=False, help="Print as json instead of rich table"),
):
    """List all files for a given address"""
    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    if account and not address:
        address = account.get_address()

    if address:
        # Build the query parameters
        query_params = GetAccountFilesQueryParams(pagination=pagination, page=page, sort_order=sort_order)

        uri = f"{settings.API_HOST}/api/v0/addresses/{address}/files"
        async with aiohttp.ClientSession() as session:
            response = await session.get(uri, params=query_params.dict())
            if response.status == 200:
                files_data = await response.json()
                formatted_files_data = json_lib.dumps(files_data, indent=4)
                if not json:
                    _show_files(files_data)
                else:
                    typer.echo(formatted_files_data)
            else:
                typer.echo(f"Failed to retrieve files for address {address}. Status code: {response.status}")
    else:
        typer.echo("Error: Please provide either a private key, private key file, or an address.")
