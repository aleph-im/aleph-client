from __future__ import annotations

import json
import logging
import sys
from base64 import b16decode, b32encode
from collections.abc import Mapping
from pathlib import Path
from typing import List, Optional, cast
from zipfile import BadZipFile

import typer
from aiohttp.client import _RequestContextManager
from aleph.sdk import AlephHttpClient, AuthenticatedAlephHttpClient
from aleph.sdk.account import _load_account
from aleph.sdk.client.vm_client import VmClient
from aleph.sdk.conf import settings
from aleph.sdk.exceptions import ForgottenMessageError, MessageNotFoundError
from aleph.sdk.query.filters import MessageFilter
from aleph.sdk.types import AccountFromPrivateKey, StorageEnum
from aleph_message.models import Chain, MessageType, ProgramMessage, StoreMessage
from aleph_message.models.execution.program import ProgramContent
from aleph_message.models.item_hash import ItemHash
from aleph_message.status import MessageStatus
from click import echo
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from aleph_client.commands import help_strings
from aleph_client.commands.utils import (
    filter_only_valid_messages,
    get_or_prompt_volumes,
    input_multiline,
    safe_getattr,
    setup_logging,
    str_to_datetime,
    yes_no_input,
)
from aleph_client.utils import AsyncTyper, create_archive, sanitize_url

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
            f"{message.chain.value}/{message.sender}/message/PROGRAM/{item_hash}\n"
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
async def delete(
    item_hash: str = typer.Argument(..., help="Item hash to unpersist"),
    reason: str = typer.Option("User deletion", help="Reason for deleting the program"),
    delete_code: bool = typer.Option(True, help="Also delete the code"),
    private_key: Optional[str] = settings.PRIVATE_KEY_STRING,
    private_key_file: Optional[Path] = settings.PRIVATE_KEY_FILE,
    print_message: bool = typer.Option(False),
    debug: bool = False,
):
    """Delete a program"""

    setup_logging(debug)

    account = _load_account(private_key, private_key_file)

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        try:
            existing_message: ProgramMessage = await client.get_message(
                item_hash=item_hash, message_type=ProgramMessage
            )
        except MessageNotFoundError:
            typer.echo("Program does not exist")
            raise typer.Exit(code=1)
        except ForgottenMessageError:
            typer.echo("Program already forgotten")
            raise typer.Exit(code=1)
        if existing_message.sender != account.get_address():
            typer.echo("You are not the owner of this program")
            raise typer.Exit(code=1)

        message, _ = await client.forget(hashes=[ItemHash(item_hash)], reason=reason)
        if delete_code:
            try:
                code_volume: StoreMessage = await client.get_message(
                    item_hash=existing_message.content.code.ref, message_type=StoreMessage
                )
            except MessageNotFoundError:
                typer.echo("Code volume does not exist. Skipping...")
            except ForgottenMessageError:
                typer.echo("Code volume already forgotten, Skipping...")
            if existing_message.sender != account.get_address():
                typer.echo("You are not the owner of this code volume, Skipping...")
            code_message, _ = await client.forget(
                hashes=[ItemHash(code_volume.item_hash)], reason=f"Deletion of program {item_hash}"
            )
            typer.echo(f"Code volume {code_volume.item_hash} has been deleted.")
        if print_message:
            typer.echo(f"{message.json(indent=4)}")
        typer.echo(f"Program {item_hash} has been deleted.")


@app.command()
async def list(
    address: Optional[str] = typer.Option(None, help="Owner address of the programs"),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    json: bool = typer.Option(default=False, help="Print as json instead of rich table"),
    debug: bool = False,
):
    """List all programs associated to an account"""

    setup_logging(debug)

    if address is None:
        account = _load_account(private_key, private_key_file)
        address = account.get_address()

    async with AlephHttpClient(api_server=settings.API_HOST) as client:
        resp = await client.get_messages(
            message_filter=MessageFilter(
                message_types=[MessageType.program],
                addresses=[address],
            ),
            page_size=100,
        )
        messages = await filter_only_valid_messages(resp.messages)
        if not messages:
            typer.echo(f"Address: {address}\n\nNo program found\n")
            raise typer.Exit(code=1)
        if json:
            for message in messages:
                typer.echo(message.json(indent=4))
        else:
            # Since we filtered on message type, we can safely cast as ProgramMessage.
            messages = cast(List[ProgramMessage], messages)

            table = Table(box=box.ROUNDED, style="blue_violet")
            table.add_column(f"Programs [{len(messages)}]", style="blue", overflow="fold")
            table.add_column("Specifications", style="magenta")
            table.add_column("Configurations", style="blue", overflow="fold")

            for message in messages:
                name = Text(
                    (
                        message.content.metadata["name"]
                        if hasattr(message.content, "metadata")
                        and isinstance(message.content.metadata, dict)
                        and "name" in message.content.metadata
                        else "-"
                    ),
                    style="orchid",
                )
                msg_link = f"https://explorer.aleph.im/address/ETH/{message.sender}/message/PROGRAM/{message.item_hash}"
                item_hash_link = Text.from_markup(f"[link={msg_link}]{message.item_hash}[/link]", style="bright_cyan")
                created_at = Text.assemble(
                    "URLs ↓\t     Created at: ",
                    Text(
                        str(str_to_datetime(str(safe_getattr(message, "content.time")))).split(".", maxsplit=1)[0],
                        style="magenta",
                    ),
                )
                hash_base32 = b32encode(b16decode(message.item_hash.upper())).strip(b"=").lower().decode()
                func_url_1 = settings.VM_URL_PATH.format(hash=message.item_hash)
                func_url_2 = settings.VM_URL_HOST.format(hash_base32=hash_base32)
                urls = Text.from_markup(
                    f"[bright_yellow][link={func_url_1}]{func_url_1}[/link][/bright_yellow]\n[dark_olive_green2][link={func_url_2}]{func_url_2}[/link][/dark_olive_green2]"
                )
                program = Text.assemble(
                    "Item Hash ↓\t     Name: ", name, "\n", item_hash_link, "\n", created_at, "\n", urls
                )
                specifications = (
                    f"vCPUs: {message.content.resources.vcpus}\n"
                    f"RAM: {message.content.resources.memory / 1_024:.2f} GiB\n"
                    "HyperV: Firecracker\n"
                    f"Timeout: {message.content.resources.seconds}s"
                )
                volumes = ""
                for volume in message.content.volumes:
                    if safe_getattr(volume, "ref"):
                        volumes += f"\n• [orchid]{volume.mount}[/orchid]: [bright_cyan][link={settings.API_HOST}/api/v0/messages/{volume.ref}]{volume.ref}[/link][/bright_cyan]"
                    elif safe_getattr(volume, "ephemeral"):
                        volumes += f"\n• [orchid]{volume.mount}[/orchid]: [bright_red]ephemeral[/bright_red]"
                    else:
                        volumes += f"\n• [orchid]{volume.mount}[/orchid]: [orange3]persistent on {volume.persistence.value}[/orange3]"
                config = Text.assemble(
                    Text.from_markup(
                        f"Runtime: [bright_cyan][link={settings.API_HOST}/api/v0/messages/{message.content.runtime.ref}]{message.content.runtime.ref}[/link][/bright_cyan]\n"
                        f"Code: [bright_cyan][link={settings.API_HOST}/api/v0/messages/{message.content.code.ref}]{message.content.code.ref}[/link][/bright_cyan]\n"
                        f"↳ Entrypoint: [orchid]{message.content.code.entrypoint}[/orchid]\n"
                    ),
                    Text.from_markup(f"Mounted Volumes: {volumes if volumes else '-'}"),
                )
                table.add_row(program, specifications, config)
                table.add_section()

            console = Console()
            console.print(table)

            infos = [
                Text.from_markup(f"[bold]Address:[/bold] [bright_cyan]{messages[0].content.address}[/bright_cyan]")
            ]
            console.print(
                Panel(
                    Text.assemble(*infos), title="Infos", border_style="bright_cyan", expand=False, title_align="left"
                )
            )


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


@app.command()
async def logs(
    item_hash: str = typer.Argument(..., help="Item hash of program"),
    private_key: Optional[str] = settings.PRIVATE_KEY_STRING,
    private_key_file: Optional[Path] = settings.PRIVATE_KEY_FILE,
    domain: str = typer.Option(None, help="CRN domain on which the VM is stored or running"),
    chain: Chain = typer.Option(None, help=help_strings.ADDRESS_CHAIN),
    debug: bool = False,
):
    """Display logs for the program.

    Will only show logs from one selected CRN"""

    setup_logging(debug)

    account = _load_account(private_key, private_key_file, chain=chain)
    domain = sanitize_url(domain)

    async with VmClient(account, domain) as client:
        async with client.operate(vm_id=item_hash, operation="logs", method="GET") as response:
            logger.debug("Request %s %s", response.url, response.status)
            if response.status != 200:
                logger.debug(response)
                logger.debug(await response.text())

            if response.status == 404:
                echo(f"Server didn't found any execution of this prorgam")
                return 1
            elif response.status == 403:

                echo(f"You are not the owner of this VM. Maybe try with another wallet?")

                return 1
            elif response.status != 200:
                echo(f"Server error: {response.status}. Please try again latter")
                return 1
            echo("Received logs")
            log_entries = await response.json()
            for log in log_entries:
                echo(f'{log["__REALTIME_TIMESTAMP"]}>  {log["MESSAGE"]}')
