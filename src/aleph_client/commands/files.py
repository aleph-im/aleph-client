import json
import logging
from pathlib import Path
from typing import Optional

import requests
import typer
from aleph.sdk import AlephHttpClient, AuthenticatedAlephHttpClient
from aleph.sdk.account import _load_account
from aleph.sdk.conf import settings as sdk_settings
from aleph.sdk.types import AccountFromPrivateKey, StorageEnum
from aleph_message.models import StoreMessage
from aleph_message.status import MessageStatus
from pydantic import BaseModel, Field

from aleph_client.commands import help_strings
from aleph_client.commands.utils import setup_logging
from aleph_client.utils import AsyncTyper

logger = logging.getLogger(__name__)
app = AsyncTyper()


@app.command()
async def pin(
    item_hash: str = typer.Argument(..., help="IPFS hash to pin on aleph.im"),
    channel: Optional[str] = typer.Option(default=None, help=help_strings.CHANNEL),
    private_key: Optional[str] = typer.Option(
        sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY
    ),
    private_key_file: Optional[Path] = typer.Option(
        sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE
    ),
    ref: Optional[str] = typer.Option(None, help=help_strings.REF),
    debug: bool = False,
):
    """Persist a file from IPFS on aleph.im."""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    async with AuthenticatedAlephHttpClient(
        account=account, api_server=sdk_settings.API_HOST
    ) as client:
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
    channel: Optional[str] = typer.Option(default=None, help=help_strings.CHANNEL),
    private_key: Optional[str] = typer.Option(
        sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY
    ),
    private_key_file: Optional[Path] = typer.Option(
        sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE
    ),
    ref: Optional[str] = typer.Option(None, help=help_strings.REF),
    debug: bool = False,
):
    """Upload and store a file on aleph.im."""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    async with AuthenticatedAlephHttpClient(
        account=account, api_server=sdk_settings.API_HOST
    ) as client:
        if not path.is_file():
            typer.echo(f"Error: File not found: '{path}'")
            raise typer.Exit(code=1)

        with open(path, "rb") as fd:
            logger.debug("Reading file")
            # TODO: Read in lazy mode instead of copying everything in memory
            file_content = fd.read()
            storage_engine = (
                StorageEnum.ipfs
                if len(file_content) > 4 * 1024 * 1024
                else StorageEnum.storage
            )
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
    use_ipfs: bool = typer.Option(
        default=False, help="Download using IPFS instead of storage"
    ),
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

    async with AlephHttpClient(api_server=sdk_settings.API_HOST) as client:
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
    reason: str = typer.Argument(..., help="reason to forget"),
    channel: Optional[str] = typer.Option(None, help="channel"),
    private_key: Optional[str] = typer.Option(
        sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY
    ),
    private_key_file: Optional[Path] = typer.Option(
        sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE
    ),
    debug: bool = False,
):
    """forget a file and his message on aleph.im."""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    async with AuthenticatedAlephHttpClient(
        account=account, api_server=sdk_settings.API_HOST
    ) as client:
        value = await client.forget(hashes=[item_hash], reason=reason, channel=channel)
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


# Your list command
@app.command()
def list(
    address: Optional[str] = typer.Option(None, help="Address"),
    private_key: Optional[str] = typer.Option(
        sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY
    ),
    private_key_file: Optional[Path] = typer.Option(
        sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE
    ),
    pagination: int = typer.Option(100, help="Maximum number of files to return."),
    page: int = typer.Option(1, help="Offset in pages."),
    sort_order: int = typer.Option(
        -1,
        help="Order in which files should be listed: -1 means most recent messages first, 1 means older messages first.",
    ),
):
    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    if account and not address:
        address = account.get_address()

    if address:
        # Build the query parameters
        query_params = GetAccountFilesQueryParams(
            pagination=pagination, page=page, sort_order=sort_order
        )

        uri = f"{sdk_settings.API_HOST}/api/v0/addresses/{address}/files"
        with requests.get(uri, params=query_params.dict()) as response:
            if response.status_code == 200:
                balance_data = response.json()
                formatted_balance_data = json.dumps(balance_data, indent=4)
                typer.echo(formatted_balance_data)
            else:
                typer.echo(
                    f"Failed to retrieve files for address {address}. Status code: {response.status_code}"
                )
    else:
        typer.echo(
            "Error: Please provide either a private key, private key file, or an address."
        )
