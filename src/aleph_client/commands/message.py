import json
import os.path
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

import typer
from aleph.sdk import AlephClient, AuthenticatedAlephClient
from aleph.sdk.account import _load_account
from aleph.sdk.types import AccountFromPrivateKey, StorageEnum
from aleph_message.models import AlephMessage, ProgramMessage

from aleph_client.commands import help_strings
from aleph_client.commands.utils import input_multiline, setup_logging
from aleph_client.conf import settings

app = typer.Typer()


@app.command()
def post(
    path: Optional[Path] = typer.Option(
        None,
        help="Path to the content you want to post. If omitted, you can input your content directly",
    ),
    type: str = typer.Option("test", help="Text representing the message object type"),
    ref: Optional[str] = typer.Option(None, help=help_strings.REF),
    channel: str = typer.Option(settings.DEFAULT_CHANNEL, help=help_strings.CHANNEL),
    private_key: Optional[str] = typer.Option(
        settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY
    ),
    private_key_file: Optional[Path] = typer.Option(
        settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE
    ),
    debug: bool = False,
):
    """Post a message on Aleph.im."""

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
        account=account, api_server=settings.API_HOST
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
    hash: str = typer.Argument(..., help="Hash reference of the message to amend"),
    private_key: Optional[str] = typer.Option(
        settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY
    ),
    private_key_file: Optional[Path] = typer.Option(
        settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE
    ),
    debug: bool = False,
):
    """Amend an existing Aleph message."""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    existing_message: AlephMessage = synchronous.get_message(item_hash=hash)

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
        account=account, api_server=settings.API_HOST
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
    channel: str = typer.Option(settings.DEFAULT_CHANNEL, help=help_strings.CHANNEL),
    private_key: Optional[str] = typer.Option(
        settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY
    ),
    private_key_file: Optional[Path] = typer.Option(
        settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE
    ),
    debug: bool = False,
):
    """Forget an existing Aleph message."""

    setup_logging(debug)

    hash_list: List[str] = hashes.split(",")

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)
    with AuthenticatedAlephClient(
        account=account, api_server=settings.API_HOST
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

    with AlephClient(api_server=settings.API_HOST) as client:
        original: AlephMessage = client.get_message(item_hash=ref)
        for message in client.watch_messages(
            refs=[ref], addresses=[original.content.address]
        ):
            typer.echo(f"{message.json(indent=indent)}")
