import typer
import logging
from typing import Optional
from aleph_client.types import AccountFromPrivateKey
from aleph_client.account import _load_account
from aleph_client.conf import settings
from pathlib import Path
import asyncio
from aleph_client import synchronous

from aleph_client.commands import help_strings

from aleph_client.asynchronous import (
    get_fallback_session,
    StorageEnum,
)

from aleph_client.commands.utils import setup_logging

from aleph_message.models import StoreMessage


logger = logging.getLogger(__name__)
app = typer.Typer()


@app.command()
def pin(
    hash: str = typer.Argument(..., help="IPFS hash to pin on Aleph.im"),
    channel: str = typer.Option(settings.DEFAULT_CHANNEL, help=help_strings.CHANNEL),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    ref: Optional[str] = typer.Option(None, help=help_strings.REF),
    debug: bool = False,
):
    """Persist a file from IPFS on Aleph.im."""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    try:
        result: StoreMessage = synchronous.create_store(
            account=account,
            file_hash=hash,
            storage_engine=StorageEnum.ipfs,
            channel=channel,
            ref=ref,
        )
        logger.debug("Upload finished")
        typer.echo(f"{result.json(indent=4)}")
    finally:
        # Prevent aiohttp unclosed connector warning
        asyncio.run(get_fallback_session().close())



@app.command()
def upload(
    path: Path = typer.Argument(..., help="Path of the file to upload"),
    channel: str = typer.Option(settings.DEFAULT_CHANNEL, help=help_strings.CHANNEL),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    ref: Optional[str] = typer.Option(None, help=help_strings.REF),
    debug: bool = False,
):
    """Upload and store a file on Aleph.im."""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    try:
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
            result: StoreMessage = synchronous.create_store(
                account=account,
                file_content=file_content,
                storage_engine=storage_engine,
                channel=channel,
                guess_mime_type=True,
                ref=ref,
            )
            logger.debug("Upload finished")
            typer.echo(f"{result.json(indent=4)}")
    finally:
        # Prevent aiohttp unclosed connector warning
        asyncio.run(get_fallback_session().close())