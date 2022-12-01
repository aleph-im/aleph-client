import typer
import os
import json
import logging
import asyncio

from pathlib import Path
from typing import Optional, Dict, List
from base64 import b32encode, b16decode
from typing import Optional, Dict, List

from aleph_message.models import (
    StoreMessage,
    ProgramMessage
)

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



from aleph_client.commands.container.save import save_tar
from aleph_client.commands.container.utils import create_container_volume

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
        result: StoreMessage = synchronous.create_store(
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

def MutuallyExclusiveBoolean():
    marker = None
    def callback(ctx: typer.Context, param: typer.CallbackParam, value: str):
        # Add cli option to group if it was called with a value
        nonlocal marker
        if value is False:
            return value
        if marker is None:
            marker = param.name
        if param.name != marker:
            raise typer.BadParameter(
                f"{param.name} is mutually exclusive with {marker}")
        return value
    return callback

exclusivity_callback = MutuallyExclusiveBoolean()

@app.command()
def upload(
    image: str = typer.Argument(..., help="Path to an image archive exported with docker save."),
    path: str = typer.Argument(..., metavar="SCRIPT", help="A small script to start your container with parameters"),
    from_remote: bool = typer.Option(False, "--from-remote", help=" If --from-remote, IMAGE is a registry to pull the image from. e.g: library/alpine, library/ubuntu:latest", callback=exclusivity_callback),
    from_daemon: bool = typer.Option(False, "--from-daemon", help=" If --from-daemon, IMAGE is an image in local docker deamon storage. You need docker installed for this command", callback=exclusivity_callback),
    from_created: bool = typer.Option(False, "--from-created", help=" If --from-created, IMAGE the path to a file created with 'aleph container create'", callback=exclusivity_callback),
    channel: str = typer.Option(settings.DEFAULT_CHANNEL, help=help_strings.CHANNEL),
    memory: int = typer.Option(settings.DEFAULT_VM_MEMORY, help="Maximum memory allocation on vm in MiB"),
    vcpus: int = typer.Option(settings.DEFAULT_VM_VCPUS, help="Number of virtual cpus to allocate."),
    timeout_seconds: float = typer.Option(settings.DEFAULT_VM_TIMEOUT, help="If vm is not called after [timeout_seconds] it will shutdown"),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    docker_mountpoint: Optional[Path] = typer.Option(settings.DEFAULT_DOCKER_VOLUME_MOUNTPOINT, "--docker-mountpoint", help="The path where the created docker image volume will be mounted"),
    optimize: bool = typer.Option(True, help="Activate volume size optimization"),
    print_messages: bool = typer.Option(False),
    print_code_message: bool = typer.Option(False),
    print_program_message: bool = typer.Option(False),
    beta: bool = False,
):
    """
    Deploy a docker container on Aleph virtual machines.
    Unless otherwise specified, you don't need docker on your machine to run this command.
    """
    typer.echo("Preparing image for vm runtime")
    docker_data_path=image
    if not from_created:
        docker_data_path = os.path.abspath("docker-data")
        try:
            create_container_volume(image, docker_data_path, from_remote, from_daemon, optimize, settings)
        except Exception as e:
            typer.echo(e)
            raise typer.Exit(1)
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
        docker_upload_layers_result: StoreMessage = upload_file(f"{docker_data_path}/layers", account, channel, print_messages, print_code_message)
        docker_upload_metadata_result: StoreMessage = upload_file(f"{docker_data_path}/metadata", account, channel, print_messages, print_code_message)
        typer.echo(f"Docker image layers upload message address: {docker_upload_layers_result.item_hash}")
        typer.echo(f"Docker image metadata upload message address: {docker_upload_metadata_result.item_hash}")

        volumes.append({
            "comment": "Docker image layers",
            "mount": f"{str(docker_mountpoint)}/layers",
            "ref": str(docker_upload_layers_result.item_hash),
            "use_latest": True,
        })

        volumes.append({
            "comment": "Docker image metadata",
            "mount": f"{str(docker_mountpoint)}/metadata",
            "ref": str(docker_upload_metadata_result.item_hash),
            "use_latest": True,
        })


        program_result: StoreMessage = upload_file(path, account, channel, print_messages, print_code_message)

        # Register the program
        result: ProgramMessage = synchronous.create_program(
            account=account,
            program_ref=program_result.item_hash,
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
                "DOCKER_MOUNTPOINT": str(docker_mountpoint)
            }
        )
        logger.debug("Upload finished")
        if print_messages or print_program_message:
            typer.echo(f"{json.dumps(result, indent=4)}")

        hash: str = result.item_hash
        hash_base32 = b32encode(b16decode(hash.upper())).strip(b"=").lower().decode()


        typer.echo(
            f"Your program has been uploaded on Aleph .\n\n"
            "Available on:\n"
            f"  {settings.VM_URL_PATH.format(hash=hash)}\n"
            f"  {settings.VM_URL_HOST.format(hash_base32=hash_base32)}\n"
            "Visualise on:\n  https://explorer.aleph.im/address/"
            f"{result.chain}/{result.sender}/message/PROGRAM/{hash}\n"
        )

    finally:
        # Prevent aiohttp unclosed connector warning
        asyncio.get_event_loop().run_until_complete(get_fallback_session().close())

@app.command()
def create(
    image: str = typer.Argument(..., help="Path to an image archive exported with docker save."),
    output: str = typer.Argument(..., help="The path where you want "),
    from_remote: bool = typer.Option(False, "--from-remote", help=" If --from-remote, IMAGE is a registry to pull the image from. e.g: library/alpine, library/ubuntu:latest", callback=exclusivity_callback),
    from_daemon: bool = typer.Option(False, "--from-daemon", help=" If --from-daemon, IMAGE is an image in local docker deamon storage. You need docker installed for this command", callback=exclusivity_callback),
    optimize: bool = typer.Option(True, help="Activate volume size optimization"),
):
    """
    Use a docker image to create an Aleph compatible image on your local machine.
    You can later upload it with 'aleph container upload --from-'
    """
    try:
        create_container_volume(image, output, from_remote, from_daemon, optimize, settings)
        typer.echo(f"Container volume created at {output}")
    except Exception as e:
        typer.echo(e)
        raise typer.Exit(1)
    return