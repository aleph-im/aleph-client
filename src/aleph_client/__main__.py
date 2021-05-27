"""Aleph Client command-line interface.
"""
import asyncio
import json
import logging
import os.path
from enum import Enum
from typing import Optional, Dict
from zipfile import ZipFile, BadZipFile

import typer
from typer import echo

from aleph_client.asynchronous import (
    get_fallback_session,
    sync_create_store,
    sync_create_post, sync_create_program,
    StorageEnum,
)
from aleph_client.chains.common import get_fallback_private_key
from aleph_client.chains.ethereum import ETHAccount

logger = logging.getLogger(__name__)
app = typer.Typer()


class KindEnum(str, Enum):
    json = "json"


def _input_multiline() -> str:
    """Prompt the user for a multiline input."""
    echo("Enter/Paste your content. Ctrl-D or Ctrl-Z ( windows ) to save it.")
    contents = ""
    while True:
        try:
            line = input()
        except EOFError:
            break
        contents += line + "\n"
    return contents


def _load_account(
    private_key_str: Optional[str] = None, private_key_file: Optional[str] = None
) -> ETHAccount:
    """Load private key from a file"""

    if private_key_str:
        if not private_key_str:
            return ETHAccount(private_key_str.encode())
        else:
            raise ValueError("Choose between a private key or a file, not both")
    elif private_key_file:
        with open(private_key_file, 'rb') as pk_fd:
            private_key: bytes = pk_fd.read()
        return ETHAccount(private_key)
    else:
        private_key = get_fallback_private_key()
        account: ETHAccount = ETHAccount(private_key=private_key)
        logger.info(f"Generated fallback private key with address {account.get_address()}")
        return account


@app.command()
def post(
    path: Optional[str] = None,
    type: str = "test",
    channel: str = "TEST",
    private_key: Optional[str] = None,
    private_key_file: Optional[str] = None,
):
    """Post a message on Aleph.im."""

    account = _load_account(private_key, private_key_file)
    storage_engine: str
    content: Dict

    if path:
        if not os.path.isfile(path):
            echo(f"Error: File not found: '{path}'")
            raise typer.Exit(code=1)

        file_size = os.path.getsize(path)
        storage_engine = "ipfs" if file_size > 4 * 1024 * 1024 else "storage"

        with open(path, "r") as fd:
            content = json.load(fd)

    else:
        content_raw = _input_multiline()
        storage_engine = "ipfs" if len(content_raw) > 4 * 1024 * 1024 else "storage"
        try:
            content = json.loads(content_raw)
        except json.decoder.JSONDecodeError:
            echo("Not valid JSON")
            raise typer.Exit(code=2)

    try:
        result = sync_create_post(
            account=account,
            post_content=content,
            post_type=type,
            ref=None,
            channel=channel,
            inline=True,
            storage_engine=storage_engine,
        )
        echo(f"{json.dumps(result, indent=4)}")
    finally:
        # Prevent aiohttp unclosed connector warning
        asyncio.get_event_loop().run_until_complete(get_fallback_session().close())


@app.command()
def upload(
    path: str,
    channel: str = "TEST",
    private_key: Optional[str] = None,
    private_key_file: Optional[str] = None,
):
    """Upload and store a file on Aleph.im."""

    account = _load_account(private_key, private_key_file)

    try:
        if not os.path.isfile(path):
            echo(f"Error: File not found: '{path}'")
            raise typer.Exit(code=1)

        with open(path, "rb") as fd:
            logger.debug("Reading file")
            # TODO: Read in lazy mode instead of copying everything in memory
            file_content = fd.read()
            storage_engine = (
                "ipfs" if len(file_content) > 4 * 1024 * 1024 else "storage"
            )
            logger.debug("Uploading file")
            result = sync_create_store(
                account=account,
                file_content=file_content,
                storage_engine=storage_engine,
                channel=channel,
            )
            logger.debug("Upload finished")
            echo(f"{json.dumps(result, indent=4)}")
    finally:
        # Prevent aiohttp unclosed connector warning
        asyncio.get_event_loop().run_until_complete(get_fallback_session().close())


@app.command()
def pin(
    hash: str,
    channel: str = "TEST",
    private_key: Optional[str] = None,
    private_key_file: Optional[str] = None,
):
    """Persist a file from IPFS on Aleph.im."""

    account = _load_account(private_key, private_key_file)

    try:
        result = sync_create_store(
            account=account,
            file_hash=hash,
            storage_engine="ipfs",
            channel=channel,
        )
        logger.debug("Upload finished")
        echo(f"{json.dumps(result, indent=4)}")
    finally:
        # Prevent aiohttp unclosed connector warning
        asyncio.get_event_loop().run_until_complete(get_fallback_session().close())


@app.command()
def program(
        path: str,
        entrypoint: str,
        channel: str = "TEST",
        private_key: Optional[str] = None,
        private_key_file: Optional[str] = None,
        print_messages: bool = False,
        print_code_message: bool = False,
        print_program_message: bool = False,
):
    """Register a program to run on Aleph.im virtual machines from a zip archive."""

    # Check that the file is a zip archive
    try:
        with open(path, "rb") as archive_file:
            with ZipFile(archive_file, 'r') as archive:
                if not archive.namelist():
                    echo("No file in the archive.")
                    raise typer.Exit(3)
    except BadZipFile:
        echo("Invalid zip archive")
        raise typer.Exit(3)

    account = _load_account(private_key, private_key_file)

    runtime = input("Ref of runtime if not default ?")
    if not runtime:
        runtime = "7162a3b9f8ca870fc06bafb3e9b14553304327bc78c7f53a4cee9445879e4fab"
        echo(f"Using default runtime {runtime}")

    data = input("Ref of additional data to pass to the program ?") \
           or None

    try:
        # Upload the source code
        with open(path, "rb") as fd:
            logger.debug("Reading file")
            # TODO: Read in lazy mode instead of copying everything in memory
            file_content = fd.read()
            storage_engine = (
                StorageEnum.ipfs if len(file_content) > 4 * 1024 * 1024 else StorageEnum.storage
            )
            logger.debug("Uploading file")
            result = sync_create_store(
                account=account,
                file_content=file_content,
                storage_engine=storage_engine,
                channel=channel,
            )
            logger.debug("Upload finished")
            if print_messages or print_code_message:
                echo(f"{json.dumps(result, indent=4)}")
            program_ref = result["item_hash"]

        # Register the program
        result = sync_create_program(
            account=account,
            program_ref=program_ref,
            entrypoint=entrypoint,
            runtime=runtime,
            data_ref=data,
            storage_engine=StorageEnum.storage,
            channel=channel,
        )
        logger.debug("Upload finished")
        if print_messages or print_program_message:
            echo(f"{json.dumps(result, indent=4)}")

        echo(f"Your program has been uploaded on Aleph .\n\n"
             f"Available on:\n  https://aleph.sh/vm/{result['item_hash']}\n"
             "Visualise on:\n  https://explorer.aleph.im/address/"
             f"{result['chain']}/{result['sender']}/message/PROGRAM/{result['item_hash']}\n"
             )

    finally:
        # Prevent aiohttp unclosed connector warning
        asyncio.get_event_loop().run_until_complete(get_fallback_session().close())


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s"
    )
    app()
