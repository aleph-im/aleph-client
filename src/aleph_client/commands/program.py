from __future__ import annotations

import json
import logging
from base64 import b16decode, b32encode
from collections.abc import Mapping
from pathlib import Path
from typing import List, Optional
from zipfile import BadZipFile

import typer
from aleph.sdk import AuthenticatedAlephHttpClient
from aleph.sdk.account import _load_account
from aleph.sdk.conf import settings
from aleph.sdk.types import AccountFromPrivateKey, StorageEnum
from aleph_message.models import ProgramMessage, StoreMessage
from aleph_message.models.execution.program import ProgramContent
from aleph_message.models.item_hash import ItemHash
from aleph_message.status import MessageStatus

from aleph_client.commands import help_strings
from aleph_client.commands.utils import (
    get_or_prompt_volumes,
    input_multiline,
    setup_logging,
    yes_no_input,
)
from aleph_client.utils import AsyncTyper, create_archive

logger = logging.getLogger(__name__)
app = AsyncTyper(no_args_is_help=True)


@app.command()
async def upload(
    path: Path = typer.Argument(..., help="Path to your source code"),
    entrypoint: str = typer.Argument(..., help="Your program entrypoint"),
    channel: Optional[str] = typer.Option(default=settings.DEFAULT_CHANNEL, help=help_strings.CHANNEL),
    memory: int = typer.Option(settings.DEFAULT_VM_MEMORY, help="Maximum memory allocation on vm in MiB"),
    vcpus: int = typer.Option(settings.DEFAULT_VM_VCPUS, help="Number of virtual cpus to allocate."),
    timeout_seconds: float = typer.Option(
        settings.DEFAULT_VM_TIMEOUT,
        help="If vm is not called after [timeout_seconds] it will shutdown",
    ),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    print_messages: bool = typer.Option(False),
    print_code_message: bool = typer.Option(False),
    print_program_message: bool = typer.Option(False),
    runtime: str = typer.Option(
        None,
        help="Hash of the runtime to use for your program. Defaults to aleph debian with Python3.8 and node. You can also create your own runtime and pin it",
    ),
    beta: bool = typer.Option(
        False,
        help="If true, you will be prompted to add message subscriptions to your program",
    ),
    debug: bool = False,
    persistent: bool = False,
    persistent_volume: Optional[List[str]] = typer.Option(None, help=help_strings.PERSISTENT_VOLUME),
    ephemeral_volume: Optional[List[str]] = typer.Option(None, help=help_strings.EPHEMERAL_VOLUME),
    immutable_volume: Optional[List[str]] = typer.Option(
        None,
        help=help_strings.IMMUTABLE_VOLUME,
    ),
):
    """Register a program to run on aleph.im. For more information, see https://docs.aleph.im/computing/"""

    setup_logging(debug)

    path = path.absolute()

    try:
        path_object, encoding = create_archive(path)
    except BadZipFile:
        typer.echo("Invalid zip archive")
        raise typer.Exit(3)
    except FileNotFoundError:
        typer.echo("No such file or directory")
        raise typer.Exit(4)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    runtime = runtime or input(f"Ref of runtime ? [{settings.DEFAULT_RUNTIME_ID}] ") or settings.DEFAULT_RUNTIME_ID

    volumes = get_or_prompt_volumes(
        persistent_volume=persistent_volume,
        ephemeral_volume=ephemeral_volume,
        immutable_volume=immutable_volume,
    )

    subscriptions: Optional[List[Mapping]] = None
    if beta and yes_no_input("Subscribe to messages ?", default=False):
        content_raw = input_multiline()
        try:
            subscriptions = json.loads(content_raw)
        except json.decoder.JSONDecodeError:
            typer.echo("Not valid JSON")
            raise typer.Exit(code=2)
    else:
        subscriptions = None

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        # Upload the source code
        with open(path_object, "rb") as fd:
            logger.debug("Reading file")
            # TODO: Read in lazy mode instead of copying everything in memory
            file_content = fd.read()
            storage_engine = StorageEnum.ipfs if len(file_content) > 4 * 1024 * 1024 else StorageEnum.storage
            logger.debug("Uploading file")
            user_code: StoreMessage
            status: MessageStatus
            user_code, status = await client.create_store(
                file_content=file_content,
                storage_engine=storage_engine,
                channel=channel,
                guess_mime_type=True,
                ref=None,
            )
            logger.debug("Upload finished")
            if print_messages or print_code_message:
                typer.echo(f"{user_code.json(indent=4)}")
            program_ref = user_code.item_hash

        # Register the program
        message, status = await client.create_program(
            program_ref=program_ref,
            entrypoint=entrypoint,
            runtime=runtime,
            storage_engine=StorageEnum.storage,
            channel=channel,
            memory=memory,
            vcpus=vcpus,
            timeout_seconds=timeout_seconds,
            persistent=persistent,
            encoding=encoding,
            volumes=volumes,
            subscriptions=subscriptions,
        )
        logger.debug("Upload finished")
        if print_messages or print_program_message:
            typer.echo(f"{message.json(indent=4)}")

        item_hash: ItemHash = message.item_hash
        hash_base32 = b32encode(b16decode(item_hash.upper())).strip(b"=").lower().decode()

        typer.echo(
            f"Your program has been uploaded on aleph.im\n\n"
            "Available on:\n"
            f"  {settings.VM_URL_PATH.format(hash=item_hash)}\n"
            f"  {settings.VM_URL_HOST.format(hash_base32=hash_base32)}\n"
            "Visualise on:\n  https://explorer.aleph.im/address/"
            f"{message.chain}/{message.sender}/message/PROGRAM/{item_hash}\n"
        )


@app.command()
async def update(
    item_hash: str = typer.Argument(..., help="Item hash to update"),
    path: Path = typer.Argument(..., help="Source path to upload"),
    private_key: Optional[str] = settings.PRIVATE_KEY_STRING,
    private_key_file: Optional[Path] = settings.PRIVATE_KEY_FILE,
    print_message: bool = True,
    debug: bool = False,
):
    """Update the code of an existing program"""

    setup_logging(debug)

    account = _load_account(private_key, private_key_file)
    path = path.absolute()

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        program_message: ProgramMessage = await client.get_message(item_hash=item_hash, message_type=ProgramMessage)
        code_ref = program_message.content.code.ref
        code_message: StoreMessage = await client.get_message(item_hash=code_ref, message_type=StoreMessage)

        try:
            path, encoding = create_archive(path)
        except BadZipFile:
            typer.echo("Invalid zip archive")
            raise typer.Exit(3)
        except FileNotFoundError:
            typer.echo("No such file or directory")
            raise typer.Exit(4)

        if encoding != program_message.content.code.encoding:
            logger.error(
                f"Code must be encoded with the same encoding as the previous version "
                f"('{encoding}' vs '{program_message.content.code.encoding}'"
            )
            raise typer.Exit(1)

        # Upload the source code
        with open(path, "rb") as fd:
            logger.debug("Reading file")
            # TODO: Read in lazy mode instead of copying everything in memory
            file_content = fd.read()
            logger.debug("Uploading file")
            message: StoreMessage
            message, status = await client.create_store(
                file_content=file_content,
                storage_engine=StorageEnum(code_message.content.item_type),
                channel=code_message.channel,
                guess_mime_type=True,
                ref=code_message.item_hash,
            )
            logger.debug("Upload finished")
            if print_message:
                typer.echo(f"{message.json(indent=4)}")


@app.command()
async def unpersist(
    item_hash: str = typer.Argument(..., help="Item hash to unpersist"),
    private_key: Optional[str] = settings.PRIVATE_KEY_STRING,
    private_key_file: Optional[Path] = settings.PRIVATE_KEY_FILE,
    debug: bool = False,
):
    """Stop a persistent virtual machine by making it non-persistent"""

    setup_logging(debug)

    account = _load_account(private_key, private_key_file)

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        message: ProgramMessage = await client.get_message(item_hash=item_hash, message_type=ProgramMessage)
        content: ProgramContent = message.content.copy()

        content.on.persistent = False
        content.replaces = message.item_hash

        message, _status, _ = await client.submit(
            content=content.dict(exclude_none=True),
            message_type=message.type,
            channel=message.channel,
        )
        typer.echo(f"{message.json(indent=4)}")
