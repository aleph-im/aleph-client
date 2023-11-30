import json
import logging
from base64 import b16decode, b32encode
from pathlib import Path
from typing import Dict, List, Optional

import typer
from aleph.sdk import AuthenticatedAlephHttpClient, AlephHttpClient
from aleph.sdk.account import _load_account
from aleph.sdk.conf import settings as sdk_settings
from aleph.sdk.types import AccountFromPrivateKey, StorageEnum
from aleph.sdk.exceptions import MessageNotFoundError, ForgottenMessageError
from aleph_message.models import (
    ItemHash,
    StoreMessage, InstanceMessage,
)

from aleph_client.commands import help_strings
from aleph_client.commands.utils import (
    input_multiline,
    prompt_for_volumes,
    setup_logging,
    volume_to_dict,
    yes_no_input,
)
from aleph_client.conf import settings
from aleph_client.utils import AsyncTyper

logger = logging.getLogger(__name__)
app = AsyncTyper()


@app.command()
def create(
    channel: Optional[str] = typer.Option(default=None, help=help_strings.CHANNEL),
    memory: int = typer.Option(
        sdk_settings.DEFAULT_VM_MEMORY, help="Maximum memory allocation on vm in MiB"
    ),
    vcpus: int = typer.Option(
        sdk_settings.DEFAULT_VM_VCPUS, help="Number of virtual cpus to allocate."
    ),
    timeout_seconds: float = typer.Option(
        sdk_settings.DEFAULT_VM_TIMEOUT,
        help="If vm is not called after [timeout_seconds] it will shutdown",
    ),
    private_key: Optional[str] = typer.Option(
        sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY
    ),
    private_key_file: Optional[Path] = typer.Option(
        sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE
    ),
    print_messages: bool = typer.Option(False),
    print_instance_message: bool = typer.Option(False),
    rootfs: str = typer.Option(
        None,
        help="Hash of the rootfs to use for your instance. Defaults to aleph debian with Python3.8 and node. You can also create your own rootfs and pin it",
    ),
    beta: bool = typer.Option(False),
    debug: bool = False,
    persistent_volume: Optional[List[str]] = typer.Option(
        None,
        help="""Takes 3 parameters                                                                                                                             
        A persistent volume is allocated on the host machine at any time                                             
        eg: Use , to seperate the parameters and no spaces                                                                   
        --persistent_volume persistence=host,name=my-volume,size=100 ./my-program main:app
        """,
    ),
    ephemeral_volume: Optional[List[str]] = typer.Option(
        None,
        help="""Takes 1 parameter Only                                           
            Ephemeral volumes can move and be removed by the host,Garbage collected basically, when the VM isn't running                                  
            eg: Use , to seperate the parameters and no spaces                                                                      
             --ephemeral-volume size_mib=100 ./my-program main:app """,
    ),
    immutable_volume: Optional[List[str]] = typer.Option(
        None,
        help="""Takes 3 parameters                                           
             Immutable volume is one whose contents do not change                                   
             eg: Use , to seperate the parameters and no spaces                                                                      
            --immutable-volume ref=25a393222692c2f73489dc6710ae87605a96742ceef7b91de4d7ec34bb688d94,use_latest=true,mount=/mnt/volume ./my-program main:app
             """,
    ),
):
    """Register a program to run on aleph.im virtual machines from a zip archive."""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    rootfs = (
            rootfs
            or input(f"Aleph ID of root volume (rootfs)? [default: {settings.DEFAULT_ROOTFS_ID}] ")
            or settings.DEFAULT_ROOTFS_ID
    )

    with AlephHttpClient(
        api_server=sdk_settings.API_HOST
    ) as client:
        rootfs_message: StoreMessage = client.get_message(
            item_hash=rootfs, message_type=StoreMessage
        )
        rootfs_size = rootfs_message.content.size

    volumes = []

    # Check if the volumes are empty
    if (
        persistent_volume is None
        or ephemeral_volume is None
        or immutable_volume is None
    ):
        for volume in prompt_for_volumes():
            volumes.append(volume)
            typer.echo("\n")

    # else parse all the volumes that have passed as the cli parameters and put it into volume list
    else:
        if len(persistent_volume) > 0:
            persistent_volume_dict = volume_to_dict(volume=persistent_volume)
            volumes.append(persistent_volume_dict)
        if len(ephemeral_volume) > 0:
            ephemeral_volume_dict = volume_to_dict(volume=ephemeral_volume)
            volumes.append(ephemeral_volume_dict)
        if len(immutable_volume) > 0:
            immutable_volume_dict = volume_to_dict(volume=immutable_volume)
            volumes.append(immutable_volume_dict)

    with AuthenticatedAlephHttpClient(
        account=account, api_server=sdk_settings.API_HOST
    ) as client:
        # Register the instance
        message, status = client.create_instance(
            account=account,
            rootfs=rootfs,
            rootfs_size=rootfs_size,
            storage_engine=StorageEnum.storage,
            channel=channel,
            memory=memory,
            vcpus=vcpus,
            timeout_seconds=timeout_seconds,
            volumes=volumes,
            # TODO: Add missing parameters
        )
        if print_messages or print_instance_message:
            typer.echo(f"{message.json(indent=4)}")

        item_hash: ItemHash = message.item_hash
        hash_base32 = (
            b32encode(b16decode(item_hash.upper())).strip(b"=").lower().decode()
        )

        typer.echo(
            f"Your instance has been deployed on aleph.im\n\n"
            "Available on:\n"
            f"  {settings.VM_URL_PATH.format(hash=item_hash)}\n"
            f"  {settings.VM_URL_HOST.format(hash_base32=hash_base32)}\n"
            "Visualise on:\n  https://explorer.aleph.im/address/"
            f"{message.chain}/{message.sender}/message/INSTANCE/{item_hash}\n"
        )


@app.command()
def delete(
    item_hash: str,
    private_key: Optional[str] = sdk_settings.PRIVATE_KEY_STRING,
    private_key_file: Optional[Path] = sdk_settings.PRIVATE_KEY_FILE,
    debug: bool = False,
):
    """Delete an instance, unallocating all resources associated with it. Immutable volumes will not be deleted."""

    setup_logging(debug)

    account = _load_account(private_key, private_key_file)

    with AuthenticatedAlephHttpClient(
        account=account, api_server=sdk_settings.API_HOST
    ) as client:
        try:
            existing_message: InstanceMessage = client.get_message(
                item_hash=item_hash, message_type=InstanceMessage
            )
        except MessageNotFoundError:
            typer.echo("Instance does not exist")
            raise typer.Exit(code=1)
        except ForgottenMessageError:
            typer.echo("Instance already forgotten")
            raise typer.Exit(code=1)
        if existing_message.sender != account.get_address():
            typer.echo("You are not the owner of this instance")
            raise typer.Exit(code=1)

        message, status = client.forget(hashes=[item_hash])
        typer.echo(f"{message.json(indent=4)}")
