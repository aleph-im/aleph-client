import json
import os.path
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import typer
from aleph.sdk import AlephClient, AuthenticatedAlephClient
from aleph.sdk.account import _load_account
from aleph.sdk.conf import settings as sdk_settings
from aleph.sdk.models import MessagesResponse
from aleph.sdk.types import AccountFromPrivateKey, StorageEnum
from aleph_message.models import AlephMessage, ItemHash, MessageType, ProgramMessage

from aleph_client.commands import help_strings
from aleph_client.commands.utils import (
    colorful_json,
    colorful_message_json,
    input_multiline,
    setup_logging,
)

app = typer.Typer()


def str_to_datetime(date: Optional[str]) -> Optional[datetime]:
    if date is None:
        return None
    try:
        date_f = float(date)
        return datetime.fromtimestamp(date_f)
    except ValueError:
        pass
    return datetime.fromisoformat(date)


@app.command()
def get(
    item_hash: str,
):
    with AlephClient(api_server=sdk_settings.API_HOST) as client:
        message = client.get_message(item_hash=ItemHash(item_hash))
    typer.echo(colorful_message_json(message))


@app.command()
def find(
    pagination: int = 200,
    page: int = 1,
    message_type: Optional[str] = None,
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
    message_type = MessageType(message_type) if message_type else None
    
    content_types_s: Optional[list[str]] = None
    content_keys_s: Optional[list[str]] = None
    refs_s: Optional[list[str]] = None
    addresses_s: Optional[list[str]] = None
    tags_s: Optional[list[str]] = None
    hashes_s: Optional[list[str]] = None
    channels_s: Optional[list[str]] = None
    chains_s: Optional[list[str]] = None

    content_types_s = content_types.split(",") if content_types else None
    content_keys_s = content_keys.split(",") if content_keys else None
    refs_s = refs.split(",") if refs else None
    addresses_s = addresses.split(",") if addresses else None
    tags_s = tags.split(",") if tags else None
    hashes_s = hashes.split(",") if hashes else None
    channels_s = channels.split(",") if channels else None
    chains_s = chains.split(",") if chains else None

    message_type = MessageType(message_type) if message_type else None

    start_time = str_to_datetime(start_date)
    end_time = str_to_datetime(end_date)

    with AlephClient(api_server=sdk_settings.API_HOST) as client:
        response: MessagesResponse = client.get_messages(
            pagination=pagination,
            page=page,
            message_type=message_type,
            content_types=content_types_s,
            content_keys=content_keys_s,
            refs=refs_s,
            addresses=addresses_s,
            tags=tags_s,
            hashes=hashes_s,
            channels=channels_s,
            chains=chains_s,
            start_date=start_time,
            end_date=end_time,
            ignore_invalid_messages=ignore_invalid_messages,
        )
    typer.echo(colorful_json(response.json(sort_keys=True, indent=4)))


@app.command()
def post(
    path: Optional[Path] = typer.Option(
        None,
        help="Path to the content you want to post. If omitted, you can input your content directly",
    ),
    type: str = typer.Option("test", help="Text representing the message object type"),
    ref: Optional[str] = typer.Option(None, help=help_strings.REF),
    channel: Optional[str] = typer.Option(default=None, help=help_strings.CHANNEL),
    private_key: Optional[str] = typer.Option(
        sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY
    ),
    private_key_file: Optional[Path] = typer.Option(
        sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE
    ),
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
        storage_engine = (
            StorageEnum.ipfs if file_size > 4 * 1024 * 1024 else StorageEnum.storage
        )

        with open(path, "r") as fd:
            content = json.load(fd)

    else:
        content_raw = input_multiline()
        storage_engine = (
            StorageEnum.ipfs
            if len(content_raw) > 4 * 1024 * 1024
            else StorageEnum.storage
        )
        try:
            content = json.loads(content_raw)
        except json.decoder.JSONDecodeError:
            typer.echo("Not valid JSON")
            raise typer.Exit(code=2)

    with AuthenticatedAlephClient(
        account=account, api_server=sdk_settings.API_HOST
    ) as client:
        result, status = client.create_post(
            post_content=content,
            post_type=type,
            ref=ref,
            channel=channel,
            inline=True,
            storage_engine=storage_engine,
        )

        typer.echo(json.dumps(result.dict(), indent=4))


@app.command()
def amend(
    item_hash: str = typer.Argument(..., help="Hash reference of the message to amend"),
    private_key: Optional[str] = typer.Option(
        sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY
    ),
    private_key_file: Optional[Path] = typer.Option(
        sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE
    ),
    debug: bool = False,
):
    """Amend an existing aleph.im message."""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    with AlephClient(api_server=sdk_settings.API_HOST) as client:
        existing_message: AlephMessage = client.get_message(item_hash=item_hash)

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

    typer.echo(new_content)
    with AuthenticatedAlephClient(
        account=account, api_server=sdk_settings.API_HOST
    ) as client:
        message, _status = client.submit(
            content=new_content.dict(),
            message_type=existing_message.type,
            channel=existing_message.channel,
        )
    typer.echo(f"{message.json(indent=4)}")


@app.command()
def forget(
    hashes: str = typer.Argument(
        ..., help="Comma separated list of hash references of messages to forget"
    ),
    reason: Optional[str] = typer.Option(
        None, help="A description of why the messages are being forgotten."
    ),
    channel: Optional[str] = typer.Option(default=None, help=help_strings.CHANNEL),
    private_key: Optional[str] = typer.Option(
        sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY
    ),
    private_key_file: Optional[Path] = typer.Option(
        sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE
    ),
    debug: bool = False,
):
    """Forget an existing aleph.im message."""

    setup_logging(debug)

    hash_list: List[str] = hashes.split(",")

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)
    with AuthenticatedAlephClient(
        account=account, api_server=sdk_settings.API_HOST
    ) as client:
        client.forget(hashes=hash_list, reason=reason, channel=channel)


@app.command()
def watch(
    ref: str = typer.Argument(..., help="Hash reference of the message to watch"),
    indent: Optional[int] = typer.Option(None, help="Number of indents to use"),
    debug: bool = False,
):
    """Watch a hash for amends and print amend hashes"""

    setup_logging(debug)

    with AlephClient(api_server=sdk_settings.API_HOST) as client:
        original: AlephMessage = client.get_message(item_hash=ref)
        for message in client.watch_messages(
            refs=[ref], addresses=[original.content.address]
        ):
            typer.echo(f"{message.json(indent=indent)}")
