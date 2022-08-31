"""Aleph Client command-line interface.
"""
import asyncio
import json
import logging
import os.path
import subprocess
import tempfile
from base64 import b32encode, b16decode
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, List
from zipfile import BadZipFile

import typer
from aleph_message.models import (
    ProgramMessage,
    StoreMessage,
    Message,
    MessageType,
    PostMessage,
    ForgetMessage,
)
from typer import echo

from aleph_client.utils import create_archive
from . import synchronous
from .asynchronous import (
    get_fallback_session,
    StorageEnum,
)
from .chains.common import get_fallback_private_key, BaseAccount
from .chains.ethereum import ETHAccount
from .chains.remote import RemoteAccount
from .conf import settings

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
) -> BaseAccount:
    """Load private key from a file"""

    if private_key_str:
        if not private_key_file:
            return ETHAccount(private_key_str.encode())
        else:
            raise ValueError("Choose between a private key or a file, not both")
    elif private_key_file:
        with open(private_key_file, "rb") as pk_fd:
            private_key: bytes = pk_fd.read()
        return ETHAccount(private_key)
    else:
        if settings.REMOTE_CRYPTO_HOST:
            logger.debug("Using remote account")
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(
                RemoteAccount.from_crypto_host(
                    host=settings.REMOTE_CRYPTO_HOST,
                    unix_socket=settings.REMOTE_CRYPTO_UNIX_SOCKET,
                )
            )
        else:
            private_key = get_fallback_private_key()
            account: ETHAccount = ETHAccount(private_key=private_key)
            logger.info(
                f"Generated fallback private key with address {account.get_address()}"
            )
            return account


def _setup_logging(debug: bool = False):
    level = logging.DEBUG if debug else logging.WARNING
    logging.basicConfig(level=level)


@app.command()
def whoami(
    private_key: Optional[str] = settings.PRIVATE_KEY_STRING,
    private_key_file: Optional[str] = settings.PRIVATE_KEY_FILE,
):
    """
    Display your public address.
    """

    account = _load_account(private_key, private_key_file)
    echo(account.get_public_key())


@app.command()
def post(
    path: Optional[str] = None,
    type: str = "test",
    ref: Optional[str] = None,
    channel: str = settings.DEFAULT_CHANNEL,
    private_key: Optional[str] = settings.PRIVATE_KEY_STRING,
    private_key_file: Optional[str] = settings.PRIVATE_KEY_FILE,
    debug: bool = False,
):
    """Post a message on Aleph.im."""

    _setup_logging(debug)

    account = _load_account(private_key, private_key_file)
    storage_engine: str
    content: Dict

    if path:
        path_object = Path(path)
        if not path_object.is_file():
            echo(f"Error: File not found: '{path_object}'")
            raise typer.Exit(code=1)

        file_size = os.path.getsize(path_object)
        storage_engine = (
            StorageEnum.ipfs if file_size > 4 * 1024 * 1024 else StorageEnum.storage
        )

        with open(path_object, "r") as fd:
            content = json.load(fd)

    else:
        content_raw = _input_multiline()
        storage_engine = (
            StorageEnum.ipfs
            if len(content_raw) > 4 * 1024 * 1024
            else StorageEnum.storage
        )
        try:
            content = json.loads(content_raw)
        except json.decoder.JSONDecodeError:
            echo("Not valid JSON")
            raise typer.Exit(code=2)

    try:
        result: PostMessage = synchronous.create_post(
            account=account,
            post_content=content,
            post_type=type,
            ref=ref,
            channel=channel,
            inline=True,
            storage_engine=storage_engine,
        )
        echo(result.json(indent=4))
    finally:
        # Prevent aiohttp unclosed connector warning
        asyncio.run(get_fallback_session().close())


@app.command()
def upload(
    path: str,
    channel: str = settings.DEFAULT_CHANNEL,
    private_key: Optional[str] = settings.PRIVATE_KEY_STRING,
    private_key_file: Optional[str] = settings.PRIVATE_KEY_FILE,
    ref: Optional[str] = None,
    debug: bool = False,
):
    """Upload and store a file on Aleph.im."""

    _setup_logging(debug)

    account = _load_account(private_key, private_key_file)
    path_object = Path(path)

    try:
        if not path_object.is_file():
            echo(f"Error: File not found: '{path_object}'")
            raise typer.Exit(code=1)

        with open(path_object, "rb") as fd:
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
            echo(f"{result.json(indent=4)}")
    finally:
        # Prevent aiohttp unclosed connector warning
        asyncio.run(get_fallback_session().close())


@app.command()
def pin(
    hash: str,
    channel: str = settings.DEFAULT_CHANNEL,
    private_key: Optional[str] = settings.PRIVATE_KEY_STRING,
    private_key_file: Optional[str] = settings.PRIVATE_KEY_FILE,
    ref: Optional[str] = None,
    debug: bool = False,
):
    """Persist a file from IPFS on Aleph.im."""

    _setup_logging(debug)

    account = _load_account(private_key, private_key_file)

    try:
        result: StoreMessage = synchronous.create_store(
            account=account,
            file_hash=hash,
            storage_engine=StorageEnum.ipfs,
            channel=channel,
            ref=ref,
        )
        logger.debug("Upload finished")
        echo(f"{result.json(indent=4)}")
    finally:
        # Prevent aiohttp unclosed connector warning
        asyncio.run(get_fallback_session().close())


def yes_no_input(text: str, default: Optional[bool] = None):
    while True:
        if default is True:
            response = input(f"{text} [Y/n] ")
        elif default is False:
            response = input(f"{text} [y/N] ")
        else:
            response = input(f"{text} ")

        if response.lower() in ("y", "yes"):
            return True
        elif response.lower() in ("n", "no"):
            return False
        elif response == "" and default is not None:
            return default
        else:
            if default is None:
                echo("Please enter 'y', 'yes', 'n' or 'no'")
            else:
                echo("Please enter 'y', 'yes', 'n', 'no' or nothing")
            continue


def _prompt_for_volumes():
    while yes_no_input("Add volume ?", default=False):
        comment = input("Description: ") or None
        mount = input("Mount: ")
        persistent = yes_no_input("Persist on VM host ?", default=False)
        if persistent:
            name = input("Volume name: ")
            size_mib = int(input("Size in MiB: "))
            yield {
                "comment": comment,
                "mount": mount,
                "name": name,
                "persistence": "host",
                "size_mib": size_mib,
            }
        else:
            ref = input("Ref: ")
            use_latest = yes_no_input("Use latest version ?", default=True)
            yield {
                "comment": comment,
                "mount": mount,
                "ref": ref,
                "use_latest": use_latest,
            }


@app.command()
def program(
    path: str,
    entrypoint: str,
    channel: str = settings.DEFAULT_CHANNEL,
    memory: int = settings.DEFAULT_VM_MEMORY,
    vcpus: int = settings.DEFAULT_VM_VCPUS,
    timeout_seconds: float = settings.DEFAULT_VM_TIMEOUT,
    private_key: Optional[str] = settings.PRIVATE_KEY_STRING,
    private_key_file: Optional[str] = settings.PRIVATE_KEY_FILE,
    print_messages: bool = False,
    print_code_message: bool = False,
    print_program_message: bool = False,
    runtime: str = None,
    beta: bool = False,
    debug: bool = False,
):
    """Register a program to run on Aleph.im virtual machines from a zip archive."""

    _setup_logging(debug)

    path_object = Path(path).absolute()

    try:
        path_object, encoding = create_archive(path_object)
    except BadZipFile:
        echo("Invalid zip archive")
        raise typer.Exit(3)
    except FileNotFoundError:
        echo("No such file or directory")
        raise typer.Exit(4)

    account = _load_account(private_key, private_key_file)

    runtime = (
        runtime
        or input(f"Ref of runtime ? [{settings.DEFAULT_RUNTIME_ID}] ")
        or settings.DEFAULT_RUNTIME_ID
    )

    volumes = []
    for volume in _prompt_for_volumes():
        volumes.append(volume)
        echo("\n")

    subscriptions: Optional[List[Dict]]
    if beta and yes_no_input("Subscribe to messages ?", default=False):
        content_raw = _input_multiline()
        try:
            subscriptions = json.loads(content_raw)
        except json.decoder.JSONDecodeError:
            echo("Not valid JSON")
            raise typer.Exit(code=2)
    else:
        subscriptions = None

    try:
        # Upload the source code
        with open(path_object, "rb") as fd:
            logger.debug("Reading file")
            # TODO: Read in lazy mode instead of copying everything in memory
            file_content = fd.read()
            storage_engine = (
                StorageEnum.ipfs
                if len(file_content) > 4 * 1024 * 1024
                else StorageEnum.storage
            )
            logger.debug("Uploading file")
            user_code: StoreMessage = synchronous.create_store(
                account=account,
                file_content=file_content,
                storage_engine=storage_engine,
                channel=channel,
                guess_mime_type=True,
                ref=None,
            )
            logger.debug("Upload finished")
            if print_messages or print_code_message:
                echo(f"{user_code.json(indent=4)}")
            program_ref = user_code.item_hash

        # Register the program
        result: ProgramMessage = synchronous.create_program(
            account=account,
            program_ref=program_ref,
            entrypoint=entrypoint,
            runtime=runtime,
            storage_engine=StorageEnum.storage,
            channel=channel,
            memory=memory,
            vcpus=vcpus,
            timeout_seconds=timeout_seconds,
            encoding=encoding,
            volumes=volumes,
            subscriptions=subscriptions,
        )
        logger.debug("Upload finished")
        if print_messages or print_program_message:
            echo(f"{result.json(indent=4)}")

        hash: str = result.item_hash
        hash_base32 = b32encode(b16decode(hash.upper())).strip(b"=").lower().decode()

        echo(
            f"Your program has been uploaded on Aleph .\n\n"
            "Available on:\n"
            f"  {settings.VM_URL_PATH.format(hash=hash)}\n"
            f"  {settings.VM_URL_HOST.format(hash_base32=hash_base32)}\n"
            "Visualise on:\n  https://explorer.aleph.im/address/"
            f"{result['chain']}/{result['sender']}/message/PROGRAM/{hash}\n"
        )

    finally:
        # Prevent aiohttp unclosed connector warning
        asyncio.run(get_fallback_session().close())


@app.command()
def update(
    hash: str,
    path: str,
    private_key: Optional[str] = settings.PRIVATE_KEY_STRING,
    private_key_file: Optional[str] = settings.PRIVATE_KEY_FILE,
    print_message: bool = True,
    debug: bool = False,
):
    """Update the code of an existing program"""

    _setup_logging(debug)

    account = _load_account(private_key, private_key_file)
    path_object = Path(path).absolute()

    try:
        raw_program_message = synchronous.get_messages(hashes=[hash])
        program_message = ProgramMessage(**raw_program_message["messages"][0])
        code_ref = program_message.content.code.ref

        raw_code_message = synchronous.get_messages(hashes=[code_ref])
        code_message = StoreMessage(**raw_code_message["messages"][0])

        try:
            encoding = create_archive(path_object)
        except BadZipFile:
            echo("Invalid zip archive")
            raise typer.Exit(3)
        except FileNotFoundError:
            echo("No such file or directory")
            raise typer.Exit(4)

        if encoding != program_message.content.code.encoding:
            logger.error(
                "Code must be encoded with the same encoding as the previous version"
            )
            raise typer.Exit(1)

        # Upload the source code
        with open(path_object, "rb") as fd:
            logger.debug("Reading file")
            # TODO: Read in lazy mode instead of copying everything in memory
            file_content = fd.read()
            logger.debug("Uploading file")
            result = synchronous.create_store(
                account=account,
                file_content=file_content,
                storage_engine=code_message.content.item_type,
                channel=code_message.channel,
                guess_mime_type=True,
                ref=code_message.item_hash,
            )
            logger.debug("Upload finished")
            if print_message:
                echo(f"{result.json(indent=4)}")
    finally:
        # Prevent aiohttp unclosed connector warning
        asyncio.run(get_fallback_session().close())


@app.command()
def amend(
    hash: str,
    private_key: Optional[str] = settings.PRIVATE_KEY_STRING,
    private_key_file: Optional[str] = settings.PRIVATE_KEY_FILE,
    debug: bool = False,
):
    """Amend an existing Aleph message."""

    _setup_logging(debug)

    account = _load_account(private_key, private_key_file)

    existing = synchronous.get_messages(hashes=[hash])
    existing_message = existing["messages"][0]

    editor: str = os.getenv("EDITOR", default="nano")
    with tempfile.NamedTemporaryFile(suffix="json") as fd:
        # Fill in message template
        fd.write(json.dumps(existing_message["content"], indent=4).encode())
        fd.seek(0)

        # Launch editor
        subprocess.run([editor, fd.name], check=True)

        # Read new message
        fd.seek(0)
        new_message = fd.read()

    new_content = json.loads(new_message)
    new_content["ref"] = existing_message["item_hash"]
    echo(new_content)
    result = synchronous.submit(
        account=account,
        content=new_content,
        message_type=existing_message["type"],
        channel=existing_message["channel"],
    )
    echo(f"{result.json(indent=4)}")


def forget_messages(
    account: BaseAccount,
    hashes: List[str],
    reason: Optional[str],
    channel: str,
):
    try:
        result: ForgetMessage = synchronous.forget(
            account=account,
            hashes=hashes,
            reason=reason,
            channel=channel,
        )
        echo(f"{result.json(indent=4)}")
    finally:
        # Prevent aiohttp unclosed connector warning
        asyncio.run(get_fallback_session().close())


@app.command()
def forget(
    hashes: str,
    reason: Optional[str] = None,
    channel: str = settings.DEFAULT_CHANNEL,
    private_key: Optional[str] = settings.PRIVATE_KEY_STRING,
    private_key_file: Optional[str] = settings.PRIVATE_KEY_FILE,
    debug: bool = False,
):
    """Forget an existing Aleph message."""

    _setup_logging(debug)

    account = _load_account(private_key, private_key_file)

    hash_list: List[str] = hashes.split(",")
    forget_messages(account, hash_list, reason, channel)


@app.command()
def forget_aggregate(
    key: str,
    reason: Optional[str] = None,
    channel: str = settings.DEFAULT_CHANNEL,
    private_key: Optional[str] = settings.PRIVATE_KEY_STRING,
    private_key_file: Optional[str] = settings.PRIVATE_KEY_FILE,
    debug: bool = False,
):
    """Forget all the messages composing an aggregate."""

    _setup_logging(debug)

    account = _load_account(private_key, private_key_file)

    message_response = synchronous.get_messages(
        addresses=[account.get_address()],
        message_type=MessageType.aggregate.value,
        content_keys=[key],
    )
    hash_list = [message["item_hash"] for message in message_response["messages"]]
    forget_messages(account, hash_list, reason, channel)


@app.command()
def watch(
    ref: str,
    indent: Optional[int] = None,
    debug: bool = False,
):
    """Watch a hash for amends and print amend hashes"""

    _setup_logging(debug)

    original_json = synchronous.get_messages(hashes=[ref])["messages"][0]
    original = Message(**original_json)

    for message in synchronous.watch_messages(
        refs=[ref], addresses=[original.content.address]
    ):
        echo(f"{message.json(indent=indent)}")


if __name__ == "__main__":
    app()
