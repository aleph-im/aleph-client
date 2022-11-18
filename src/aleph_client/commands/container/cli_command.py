import typer
import os
import json
import logging
import asyncio

from pathlib import Path
from typing import Optional, Dict, List
from base64 import b32encode, b16decode
from typing import Optional, Dict, List

from aleph_message.models import StoreMessage

from aleph_client import synchronous
from aleph_client.account import _load_account, AccountFromPrivateKey
from aleph_client.conf import settings
from aleph_message.models.program import Encoding  # type: ignore
from aleph_client.commands import help_strings
from aleph_client.account import _load_account

from aleph_client.asynchronous import (
    get_fallback_session,
    StorageEnum,
)

from aleph_client.commands.utils import (
    yes_no_input,
    input_multiline,
    prompt_for_volumes,
    yes_no_input
)

from .save import save_tar

logger = logging.getLogger(__name__)
app = typer.Typer()

def upload_file(
    path: str,
    account: AccountFromPrivateKey,
    channel: str,
    print_messages: bool = False,
    print_code_message: bool = False
) -> StoreMessage:
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
        result = synchronous.create_store(
            account=account,
            file_content=file_content,
            storage_engine=storage_engine,
            channel=channel,
            guess_mime_type=True,
            ref=None,
        )
        logger.debug("Upload finished")
        if print_messages or print_code_message:
            typer.echo(f"{json.dumps(result, indent=4)}")
        return result

@app.command()
def upload(
    image: str = typer.Argument(..., help="Path to an image archive exported with docker save."),
    path: str = typer.Argument(..., metavar="SCRIPT", help="A small script to start your container with parameters"),
    from_remote: bool = typer.Option(False, "--from-remote", "-r", help=" If --from-remote, IMAGE is a registry to pull the image from. e.g: library/alpine, library/ubuntu:latest"),
    from_daemon: bool = typer.Option(False, "--from-daemon", "-d", help=" If --from-daemon, IMAGE is an image in local docker deamon storage. You need docker installed for this command"),
    channel: str = typer.Option(settings.DEFAULT_CHANNEL, help=help_strings.CHANNEL),
    memory: int = typer.Option(settings.DEFAULT_VM_MEMORY, help="Maximum memory allocation on vm in MiB"),
    vcpus: int = typer.Option(settings.DEFAULT_VM_VCPUS, help="Number of virtual cpus to allocate."),
    timeout_seconds: float = typer.Option(settings.DEFAULT_VM_TIMEOUT, help="If vm is not called after [timeout_seconds] it will shutdown"),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    docker_mountpoint: Optional[Path] = typer.Option(settings.DEFAULT_DOCKER_VOLUME_MOUNTPOINT, "--docker-mountpoint", help="The path where the created docker image volume will be mounted"),
    print_messages: bool = typer.Option(False),
    print_code_message: bool = typer.Option(False),
    print_program_message: bool = typer.Option(False),
    beta: bool = False,
):
    """
    Deploy a docker container on Aleph virtual machines.
    Unless otherwise specified, you don't need docker on your machine to run this command.
    """
    if from_remote or from_daemon:
        raise NotImplementedError()
        # echo(f"Downloading {image}")
        # registry = Registry()
        # tag = "latest"
        # if ":" in image:
        #     l = image.split(":")
        #     tag = l[-1]
        #     image = l[0]
        # print(tag)
        # image_object = registry.pull_image(image, tag)
        # manifest = registry.get_manifest_configuration(image, tag)
        # image_archive = os.path.abspath(f"{str(uuid4())}.tar")
        # image_object.write_filename(image_archive)
        # image = image_archive
        # print(manifest)
    typer.echo("Preparing image for vm runtime")
    docker_data_path = os.path.abspath("docker-data")
    save_tar(image, docker_data_path, settings=settings.DOCKER_SETTINGS)
    if not settings.CODE_USES_SQUASHFS:
        typer.echo("The command mksquashfs must be installed!")
        typer.Exit(2)
    logger.debug("Creating squashfs archive...")
    os.system(f"mksquashfs {docker_data_path} {docker_data_path}.squashfs -noappend")
    docker_data_path = f"{docker_data_path}.squashfs"
    assert os.path.isfile(docker_data_path)
    encoding = Encoding.squashfs
    path = os.path.abspath(path)
    entrypoint = path

    account = _load_account(private_key, private_key_file)


    volumes = []
    for volume in prompt_for_volumes():
        volumes.append(volume)
        print()

    subscriptions: Optional[List[Dict]]
    if beta and yes_no_input("Subscribe to messages ?", default=False):
        content_raw = input_multiline()
        try:
            subscriptions = json.loads(content_raw)
        except json.decoder.JSONDecodeError:
            typer.echo("Not valid JSON")
            raise typer.Exit(code=2)
    else:
        subscriptions = None

    try:
        docker_upload_result: StoreMessage = upload_file(docker_data_path, account, channel, print_messages, print_code_message)
        volumes.append({
            "comment": "Docker container volume",
            "mount": docker_mountpoint,
            "ref": docker_upload_result["item_hash"],
            "use_latest": True,
        })
        program_result: StoreMessage = upload_file(path, account, channel, print_messages, print_code_message)

        # Register the program
        result = synchronous.create_program(
            account=account,
            program_ref=program_result["item_hash"],
            entrypoint=entrypoint,
            runtime=settings.DEFAULT_DOCKER_RUNTIME_ID,
            storage_engine=StorageEnum.storage,
            channel=channel,
            memory=memory,
            vcpus=vcpus,
            timeout_seconds=timeout_seconds,
            encoding=encoding,
            volumes=volumes,
            subscriptions=subscriptions,
            environment_variables={
                "DOCKER_MOUNTPOINT": docker_mountpoint
            }
        )
        logger.debug("Upload finished")
        if print_messages or print_program_message:
            typer.echo(f"{json.dumps(result, indent=4)}")

        hash: str = result["item_hash"]
        hash_base32 = b32encode(b16decode(hash.upper())).strip(b"=").lower().decode()

        typer.echo(
            f"Your program has been uploaded on Aleph .\n\n"
            "Available on:\n"
            f"  {settings.VM_URL_PATH.format(hash=hash)}\n"
            f"  {settings.VM_URL_HOST.format(hash_base32=hash_base32)}\n"
            "Visualise on:\n  https://explorer.aleph.im/address/"
            f"{result['chain']}/{result['sender']}/message/PROGRAM/{hash}\n"
        )

    finally:
        # Prevent aiohttp unclosed connector warning
        asyncio.get_event_loop().run_until_complete(get_fallback_session().close())
