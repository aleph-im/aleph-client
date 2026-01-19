from __future__ import annotations

import json as json_lib
import logging
import time
from datetime import datetime
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Optional
from urllib.parse import urlparse

import aiohttp
import typer
from aiohttp import ClientResponseError
from aleph.sdk import AlephHttpClient, AuthenticatedAlephHttpClient
from aleph.sdk.conf import settings
from aleph.sdk.exceptions import InsufficientFundsError
from aleph.sdk.types import StorageEnum, StoredContent, TokenType
from aleph.sdk.utils import safe_getattr
from aleph_message.models import Chain, ItemHash, ItemType, MessageType, StoreMessage
from aleph_message.status import MessageStatus
from pydantic import BaseModel, Field
from rich import box
from rich.console import Console
from rich.table import Table

from aleph_client.commands import help_strings
from aleph_client.commands.utils import setup_logging
from aleph_client.utils import (
    AccountTypes,
    AsyncTyper,
    get_account_and_address,
    load_account,
)

logger = logging.getLogger(__name__)
app = AsyncTyper(no_args_is_help=True)


@app.command()
async def pin(
    item_hash: Annotated[str, typer.Argument(help="IPFS hash to pin on Aleph Cloud")],
    channel: Annotated[Optional[str], typer.Option(help=help_strings.CHANNEL)] = settings.DEFAULT_CHANNEL,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    chain: Annotated[Optional[Chain], typer.Option(help=help_strings.ADDRESS_CHAIN)] = None,
    ref: Annotated[Optional[str], typer.Option(help=help_strings.REF)] = None,
    address: Annotated[Optional[str], typer.Option(help="Address")] = None,
    debug: Annotated[bool, typer.Option()] = False,
):
    """Persist a file from IPFS on Aleph Cloud."""

    setup_logging(debug)

    account: AccountTypes = load_account(private_key_str=private_key, private_key_file=private_key_file, chain=chain)
    address = address or settings.ADDRESS_TO_USE or account.get_address()

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        result: StoreMessage
        status: MessageStatus
        result, status = await client.create_store(
            address=address,
            file_hash=item_hash,
            storage_engine=StorageEnum.ipfs,
            channel=channel,
            ref=ref,
        )
        logger.debug("Upload finished")
        typer.echo(f"{result.model_dump_json(indent=4)}")


@app.command()
async def upload(
    path: Annotated[Path, typer.Argument(help="Path of the file or directory to upload")],
    storage_engine: Annotated[Optional[StorageEnum], typer.Option(help=help_strings.STORAGE_ENGINE)] = None,
    channel: Annotated[Optional[str], typer.Option(help=help_strings.CHANNEL)] = settings.DEFAULT_CHANNEL,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    chain: Annotated[Optional[Chain], typer.Option(help=help_strings.ADDRESS_CHAIN)] = None,
    ref: Annotated[Optional[str], typer.Option(help=help_strings.REF)] = None,
    address: Annotated[Optional[str], typer.Option(help="Address")] = None,
    debug: Annotated[bool, typer.Option()] = False,
):
    """Upload and store a file or directory on Aleph Cloud."""

    setup_logging(debug)

    account: AccountTypes = load_account(private_key_str=private_key, private_key_file=private_key_file, chain=chain)
    address = address or settings.ADDRESS_TO_USE or account.get_address()

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:

        async def check_spending_capacity_for_account(storage_size_mib: float, address):
            # estimate and check before uploading
            content = {
                "address": address,
                "time": time.time(),
                "item_type": ItemType.storage,
                "estimated_size_mib": int(storage_size_mib),
                "item_hash": sha256(b"dummy value").hexdigest(),
            }
            signed_message = await client.generate_signed_message(
                message_type=MessageType.store,
                content=content,
                channel="TEST",
            )
            m = signed_message.model_dump(exclude_none=True)
            response = await client.http_session.post("/api/v0/price/estimate", json={"message": m})

            if response.status == 200:
                price = await response.json()
                required_tokens = price["required_tokens"] if price["cost"] is None else Decimal(price["cost"])

                balance_response = await client.get_balances(address)
                available_funds = balance_response.balance - balance_response.locked_amount

                try:
                    if available_funds < required_tokens:
                        raise InsufficientFundsError(TokenType.ALEPH, float(required_tokens), float(available_funds))
                except InsufficientFundsError as e:
                    typer.echo(e)
                    raise typer.Exit(code=1) from e

        if path.is_file():
            with open(path, "rb") as fd:
                logger.debug("Reading file")
                # TODO: Read in lazy mode instead of copying everything in memory
                file_content = fd.read()
                file_size = len(file_content)

                # check spending limit
                await check_spending_capacity_for_account(file_size / 1_024 / 1_024, address)

                storage_limit = 4 * 1024 * 1024  # 4MB
                if storage_engine is None:
                    storage_engine = StorageEnum.ipfs if file_size > storage_limit else StorageEnum.storage
                if storage_engine == StorageEnum.storage and file_size > storage_limit:
                    typer.echo("Warning: File is larger than 4MB, switching to IPFS storage.")
                    storage_engine = StorageEnum.ipfs

                logger.debug("Uploading file")
                result: StoreMessage
                status: MessageStatus
                try:
                    result, status = await client.create_store(
                        address=address,
                        file_content=file_content,
                        storage_engine=storage_engine,
                        channel=channel,
                        guess_mime_type=True,
                        ref=ref,
                    )
                    logger.debug("Upload finished")
                    typer.echo(f"{result.model_dump_json(indent=4)}")
                except ClientResponseError as e:
                    typer.echo(f"{e}")

                    if e.status == 413:
                        typer.echo("File is too large to be uploaded. Please use aleph file pin")
                    else:
                        typer.echo(f"Error uploading file\nstatus: {e.status}\nmessage: {e.message}")

        elif path.is_dir():
            typer.echo(f"Upload directory {path}...")

            async def upload_directory(directory: Path):
                params = {"recursive": "true", "wrap-with-directory": "true"}

                files = {}
                for _path in directory.rglob("*"):
                    if _path.is_file():
                        relative_path = _path.relative_to(directory)
                        files[str(relative_path)] = open(_path, "rb")

                url = urlparse(settings.IPFS_GATEWAY)._replace(path="/api/v0/add").geturl()
                async with aiohttp.ClientSession() as session:
                    response = await session.post(url, params=params, data=files)
                    response.raise_for_status()

                    # Parse the response line-by-line
                    cid_v0 = None
                    data = await response.text()
                    for line in data.strip().splitlines():
                        entry = json_lib.loads(line)
                        cid_v0 = entry.get("Hash")

                    if not cid_v0:
                        return None

                    return cid_v0

            total_size = 0
            for fp in path.rglob("*"):
                if fp.is_file():
                    total_size += fp.stat().st_size

            await check_spending_capacity_for_account(total_size / 1_024 / 1_024, address)
            cid = await upload_directory(path)
            if not cid:
                typer.echo("CID not found in response.")
                typer.Exit(code=1)
            await pin(cid, channel, private_key, private_key_file, chain, ref, address, debug)
        else:
            typer.echo(f"Error: File not found: '{path}'")
            raise typer.Exit(code=1)


@app.command()
async def download(
    hash: Annotated[str, typer.Argument(help="hash to download from aleph.")],
    use_ipfs: Annotated[bool, typer.Option(help="Download using IPFS instead of storage")] = False,
    output_path: Annotated[Path, typer.Option(help="Output directory path")] = Path("."),
    file_name: Annotated[Optional[str], typer.Option(help="Output file name (without extension)")] = None,
    file_extension: Annotated[Optional[str], typer.Option(help="Output file extension")] = None,
    only_info: Annotated[bool, typer.Option()] = False,
    verbose: Annotated[bool, typer.Option()] = True,
    debug: Annotated[bool, typer.Option()] = False,
) -> Optional[StoredContent]:
    """Download a file from Aleph Cloud or display related infos."""

    setup_logging(debug)

    if not only_info:
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
    else:
        async with AlephHttpClient(api_server=settings.API_HOST) as client:
            content = await client.get_stored_content(hash)
            if verbose:
                typer.echo(
                    f"Filename: {content.filename}\nHash: {content.hash}\nURL: {content.url}"
                    if safe_getattr(content, "url")
                    else safe_getattr(content, "error")
                )
            return content
    return None


@app.command()
async def forget(
    item_hash: Annotated[
        str,
        typer.Argument(
            help="Hash(es) to forget. Must be a comma separated list. Example: `123...abc` or `123...abc,456...xyz`"
        ),
    ],
    reason: Annotated[str, typer.Argument(help="reason to forget")] = "User deletion",
    channel: Annotated[Optional[str], typer.Option(help=help_strings.CHANNEL)] = settings.DEFAULT_CHANNEL,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    chain: Annotated[Optional[Chain], typer.Option(help=help_strings.ADDRESS_CHAIN)] = None,
    debug: Annotated[bool, typer.Option()] = False,
):
    """Forget a file and his message on Aleph Cloud."""

    setup_logging(debug)

    account: AccountTypes = load_account(private_key_str=private_key, private_key_file=private_key_file, chain=chain)

    hashes = [ItemHash(item_hash) for item_hash in item_hash.split(",")]

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        value = await client.forget(hashes=hashes, reason=reason, channel=channel)
        typer.echo(f"{value[0].model_dump_json(indent=4)}")


class GetAccountFilesQueryParams(BaseModel):
    pagination: int = Field(
        default=100,
        ge=0,
        description="Maximum number of files to return. Specifying 0 removes this limit.",
    )
    page: int = Field(default=1, ge=1, description="Offset in pages. Starts at 1.")
    sort_order: int = Field(
        default=-1,
        description=(
            "Order in which files should be listed: -1 means most recent messages first, 1 means older messages first."
        ),
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


@app.command(name="list")
async def list_files(
    address: Annotated[Optional[str], typer.Option(help="Address")] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    chain: Annotated[Optional[Chain], typer.Option(help=help_strings.ADDRESS_CHAIN)] = None,
    pagination: Annotated[int, typer.Option(help="Maximum number of files to return.")] = 100,
    page: Annotated[int, typer.Option(help="Offset in pages.")] = 1,
    sort_order: Annotated[
        int,
        typer.Option(
            help="Order in which files should be listed: -1 means most recent messages first,"
            " 1 means older messages first."
        ),
    ] = -1,
    json: Annotated[bool, typer.Option(help="Print as json instead of rich table")] = False,
):
    """List all files for a given address"""
    account, address = get_account_and_address(
        private_key=private_key, private_key_file=private_key_file, address=address, chain=chain
    )

    if address:
        # Build the query parameters
        query_params = GetAccountFilesQueryParams(pagination=pagination, page=page, sort_order=sort_order)

        uri = f"{settings.API_HOST}/api/v0/addresses/{address}/files"
        async with aiohttp.ClientSession() as session:
            response = await session.get(uri, params=query_params.model_dump())
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
