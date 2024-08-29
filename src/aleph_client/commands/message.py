from __future__ import annotations

import asyncio
import json
import os.path
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional

import typer
from aleph.sdk import AlephHttpClient, AuthenticatedAlephHttpClient
from aleph.sdk.account import _load_account
from aleph.sdk.conf import settings
from aleph.sdk.query.filters import MessageFilter
from aleph.sdk.query.responses import MessagesResponse
from aleph.sdk.types import AccountFromPrivateKey, StorageEnum
from aleph.sdk.utils import extended_json_encoder
from aleph_message.models import AlephMessage, ProgramMessage
from aleph_message.models.base import MessageType
from aleph_message.models.item_hash import ItemHash
from aleph_message.status import MessageStatus

from aleph_client.commands import help_strings
from aleph_client.commands.utils import (
    colorful_json,
    colorful_message_json,
    colorized_status,
    input_multiline,
    setup_logging,
    str_to_datetime,
)
from aleph_client.utils import AsyncTyper

app = AsyncTyper(no_args_is_help=True)


@app.command()
async def get(
    item_hash: str = typer.Argument(..., help="Item hash of the message"),
):
    async with AlephHttpClient(api_server=settings.API_HOST) as client:
        message, status = await client.get_message(item_hash=ItemHash(item_hash), with_status=True)
        typer.echo(f"Message Status: {colorized_status(status)}")
        if status == MessageStatus.REJECTED:
            reason = await client.get_message_error(item_hash=ItemHash(item_hash))
            typer.echo(colorful_json(json.dumps(reason, indent=4)))
        else:
            typer.echo(colorful_message_json(message))


@app.command()
async def find(
    pagination: int = 200,
    page: int = 1,
    message_types: Optional[str] = None,
    content_types: Optional[str] = None,
    content_keys: Optional[str] = None,
    refs: Optional[str] = None,
    addresses: Optional[str] = None,
    tags: Optional[str] = None,
    hashes: Optional[str] = None,
    channels: Optional[str] = None,
    chains: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    ignore_invalid_messages: bool = True,
):
    parsed_message_types = (
        [MessageType(message_type) for message_type in message_types.split(",")] if message_types else None
    )
    parsed_content_types = content_types.split(",") if content_types else None
    parsed_content_keys = content_keys.split(",") if content_keys else None
    parsed_refs = refs.split(",") if refs else None
    parsed_addresses = addresses.split(",") if addresses else None
    parsed_tags = tags.split(",") if tags else None
    parsed_hashes = hashes.split(",") if hashes else None
    parsed_channels = channels.split(",") if channels else None
    parsed_chains = chains.split(",") if chains else None

    start_time = str_to_datetime(start_date)
    end_time = str_to_datetime(end_date)

    async with AlephHttpClient(api_server=settings.API_HOST) as client:
        response: MessagesResponse = await client.get_messages(
            page_size=pagination,
            page=page,
            message_filter=MessageFilter(
                message_types=parsed_message_types,
                content_types=parsed_content_types,
                content_keys=parsed_content_keys,
                refs=parsed_refs,
                addresses=parsed_addresses,
                tags=parsed_tags,
                hashes=parsed_hashes,
                channels=parsed_channels,
                chains=parsed_chains,
                start_date=start_time,
                end_date=end_time,
            ),
            ignore_invalid_messages=ignore_invalid_messages,
        )
    typer.echo(colorful_json(response.json(sort_keys=True, indent=4)))


@app.command()
async def post(
    path: Optional[Path] = typer.Option(
        None,
        help="Path to the content you want to post. If omitted, you can input your content directly",
    ),
    type: str = typer.Option("test", help="Text representing the message object type"),
    ref: Optional[str] = typer.Option(None, help=help_strings.REF),
    channel: Optional[str] = typer.Option(default=settings.DEFAULT_CHANNEL, help=help_strings.CHANNEL),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    """Post a message on aleph.im."""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)
    storage_engine: StorageEnum
    content: Dict

    if path:
        if not path.is_file():
            typer.echo(f"Error: File not found: '{path}'")
            raise typer.Exit(code=1)

        file_size = os.path.getsize(path)
        storage_engine = StorageEnum.ipfs if file_size > 4 * 1024 * 1024 else StorageEnum.storage

        with open(path) as fd:
            content = json.load(fd)

    else:
        content_raw = input_multiline()
        storage_engine = StorageEnum.ipfs if len(content_raw) > 4 * 1024 * 1024 else StorageEnum.storage
        try:
            content = json.loads(content_raw)
        except json.decoder.JSONDecodeError:
            typer.echo("Not valid JSON")
            raise typer.Exit(code=2)

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        result, status = await client.create_post(
            post_content=content,
            post_type=type,
            ref=ref,
            channel=channel,
            inline=True,
            storage_engine=storage_engine,
        )

        typer.echo(json.dumps(result.dict(), indent=4, default=extended_json_encoder))


@app.command()
async def amend(
    item_hash: str = typer.Argument(..., help="Hash reference of the message to amend"),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    """Amend an existing aleph.im message."""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    async with AlephHttpClient(api_server=settings.API_HOST) as client:
        existing_message: AlephMessage = await client.get_message(item_hash=item_hash)

    editor: str = os.getenv("EDITOR", default="nano")
    with tempfile.NamedTemporaryFile(suffix="json") as fd:
        # Fill in message template
        fd.write(existing_message.content.json(indent=4).encode())
        fd.seek(0)

        # Launch editor
        subprocess.run([editor, fd.name], check=True)

        # Read new message
        fd.seek(0)
        new_content_json = fd.read()

    content_type = type(existing_message).__annotations__["content"]
    new_content_dict = json.loads(new_content_json)
    new_content = content_type(**new_content_dict)

    if isinstance(existing_message, ProgramMessage):
        new_content.replaces = existing_message.item_hash
    else:
        new_content.ref = existing_message.item_hash

    new_content.time = time.time()
    new_content.type = "amend"

    typer.echo(new_content)
    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        message, status, response = await client.submit(
            content=new_content.dict(),
            message_type=existing_message.type,
            channel=existing_message.channel,
        )
    typer.echo(f"{message.json(indent=4)}")


@app.command()
async def forget(
    hashes: str = typer.Argument(..., help="Comma separated list of hash references of messages to forget"),
    reason: Optional[str] = typer.Option(None, help="A description of why the messages are being forgotten."),
    channel: Optional[str] = typer.Option(default=settings.DEFAULT_CHANNEL, help=help_strings.CHANNEL),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    """Forget an existing aleph.im message."""

    setup_logging(debug)

    hash_list: List[ItemHash] = [ItemHash(h) for h in hashes.split(",")]

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)
    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        await client.forget(hashes=hash_list, reason=reason, channel=channel)


@app.command()
async def watch(
    ref: str = typer.Argument(..., help="Hash reference of the message to watch"),
    indent: Optional[int] = typer.Option(None, help="Number of indents to use"),
    debug: bool = False,
):
    """Watch a hash for amends and print amend hashes"""

    setup_logging(debug)

    async with AlephHttpClient(api_server=settings.API_HOST) as client:
        original: AlephMessage = await client.get_message(item_hash=ref)
        async for message in client.watch_messages(
            message_filter=MessageFilter(refs=[ref], addresses=[original.content.address])
        ):
            typer.echo(f"{message.json(indent=indent)}")


@app.command()
def sign(
    message: Optional[str] = typer.Option(None, help=help_strings.SIGNABLE_MESSAGE),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    """Sign an aleph message with a private key. If no --message is provided, the message will be read from stdin."""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    if message is None:
        # take from stdin
        message = "\n".join(sys.stdin.readlines())

    coroutine = account.sign_message(json.loads(message))
    signed_message = asyncio.run(coroutine)
    typer.echo(json.dumps(signed_message, indent=4, default=extended_json_encoder))
