import typer
import os
import json
import magic
import logging
import asyncio

from typing import Optional, Dict, List
from shutil import make_archive
from aleph_client.account import _load_account
from aleph_client.conf import settings
from aleph_message.models.program import Encoding  # type: ignore

from aleph_client import synchronous

from base64 import b32encode, b16decode
from typing import Optional, Dict, List

from typing import Optional, Dict, List
from .container.save import save_tar

from aleph_client.account import _load_account

logger = logging.getLogger(__name__)
app = typer.Typer()



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

app = typer.Typer()

@app.command()
def container(
    image: str = typer.Argument(..., help="Path to an image archive exported with docker save."),
    path: str = typer.Argument(..., metavar="SCRIPT", help="A small script to start your container with parameters"),
    remote: bool = typer.Option(False, "--remote", "-r", help=" If --remote, IMAGE is a registry to pull the image from. e.g: library/alpine, library/ubuntu:latest"),
    from_daemon: bool = typer.Option(False, "--from-daemon", "-d", help=" If --from-daemon, IMAGE is an image in local docker deamon storage. You need docker installed for this command"),
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
):
    """
    Deploy a docker container on Aleph virtual machines.
    Unless otherwise specified, you don't need docker on your machine to run this command.
    """
    if remote or from_daemon:
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
    if settings.CODE_USES_SQUASHFS:
        logger.debug("Creating squashfs archive...")
        os.system(f"mksquashfs {docker_data_path} {docker_data_path}.squashfs -noappend")
        docker_data_path = f"{docker_data_path}.squashfs"
        assert os.path.isfile(docker_data_path)
        encoding = Encoding.squashfs
    path = os.path.abspath(path)
    entrypoint = path

    # Create a zip archive from a directory
    if os.path.isdir(path):
        if settings.CODE_USES_SQUASHFS:
            logger.debug("Creating squashfs archive...")
            os.system(f"mksquashfs {path} {path}.squashfs -noappend")
            path = f"{path}.squashfs"
            assert os.path.isfile(path)
            encoding = Encoding.squashfs
        else:
            logger.debug("Creating zip archive...")
            make_archive(path, "zip", path)
            path = path + ".zip"
            encoding = Encoding.zip
    elif os.path.isfile(path):
        if path.endswith(".squashfs") or (
            magic and magic.from_file(path).startswith("Squashfs filesystem")
        ):
            encoding = Encoding.squashfs
        elif _is_zip_valid(path):
            encoding = Encoding.zip
        else:
            raise typer.Exit(3)
    else:
        typer.echo("No such file or directory")
        raise typer.Exit(4)

    account = _load_account(private_key, private_key_file)

    runtime = (
        runtime
        or input(f"Ref of runtime ? [{settings.DEFAULT_RUNTIME_ID}] ")
        or settings.DEFAULT_RUNTIME_ID
    )

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
        # Upload the source code
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
            program_ref = result["item_hash"]

        # Register the program
        result = synchronous.create_program(
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
