import logging
from pathlib import Path
from typing import Optional

import typer
from aleph.sdk import AuthenticatedAlephClient
from aleph.sdk.account import _load_account
from aleph.sdk.conf import settings as sdk_settings
from aleph.sdk.types import AccountFromPrivateKey, StorageEnum
from aleph_message.models import StoreMessage
from aleph_message.status import MessageStatus

from aleph_client.commands import help_strings
from aleph_client.commands.utils import setup_logging

logger = logging.getLogger(__name__)
app = typer.Typer()


@app.command()
def pin(
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

    with AuthenticatedAlephClient(
        account=account, api_server=sdk_settings.API_HOST
    ) as client:
        result: StoreMessage
        status: MessageStatus
        result, status = client.create_store(
            file_hash=item_hash,
            storage_engine=StorageEnum.ipfs,
            channel=channel,
            ref=ref,
        )
        logger.debug("Upload finished")
        typer.echo(f"{result.json(indent=4)}")


@app.command()
def upload(
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

    with AuthenticatedAlephClient(
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
            result, status = client.create_store(
                file_content=file_content,
                storage_engine=storage_engine,
                channel=channel,
                guess_mime_type=True,
                ref=ref,
            )
            logger.debug("Upload finished")
            typer.echo(f"{result.json(indent=4)}")
