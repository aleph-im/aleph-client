import logging
from base64 import b16decode, b32encode
from pathlib import Path
from typing import List, Optional, Union

import typer
from aleph.sdk import AlephHttpClient, AuthenticatedAlephHttpClient
from aleph.sdk.account import _load_account
from aleph.sdk.conf import settings as sdk_settings
from aleph.sdk.exceptions import ForgottenMessageError, MessageNotFoundError
from aleph.sdk.types import AccountFromPrivateKey, StorageEnum
from aleph_message.models import InstanceMessage, ItemHash, StoreMessage

from aleph_client.commands import help_strings
from aleph_client.commands.utils import (
    get_or_prompt_volumes,
    setup_logging,
    validated_prompt,
)
from aleph_client.conf import settings
from aleph_client.utils import AsyncTyper

logger = logging.getLogger(__name__)
app = AsyncTyper()


def load_ssh_pubkey(ssh_pubkey_file: Path) -> str:
    with open(ssh_pubkey_file, "r") as f:
        return f.read().strip()


@app.command()
async def create(
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
    ssh_pubkey_file: Path = typer.Option(
        Path("~/.ssh/id_rsa.pub").expanduser(),
        help="Path to a public ssh key to be added to the instance.",
    ),
    print_messages: bool = typer.Option(False),
    rootfs: str = typer.Option(
        None,
        help="Hash of the rootfs to use for your instance. Defaults to aleph debian with Python3.8 and node. You can also create your own rootfs and pin it",
    ),
    rootfs_name: Optional[str] = typer.Option(
        None,
        help="Name of the rootfs to use for your instance. If not set, content.metadata.name of the --rootfs store message will be used.",
    ),
    rootfs_size: Optional[int] = typer.Option(
        None,
        help="Size of the rootfs to use for your instance. If not set, content.size of the --rootfs store message will be used.",
    ),
    debug: bool = False,
    persistent_volume: Optional[List[str]] = typer.Option(
        None, help=help_strings.PERSISTENT_VOLUME
    ),
    ephemeral_volume: Optional[List[str]] = typer.Option(
        None, help=help_strings.EPHEMERAL_VOLUME
    ),
    immutable_volume: Optional[List[str]] = typer.Option(
        None,
        help=help_strings.IMMUATABLE_VOLUME,
    ),
):
    """Register a new instance on aleph.im"""

    setup_logging(debug)

    def validate_ssh_pubkey_file(file: Union[str, Path]) -> Path:
        if isinstance(file, str):
            file = Path(file).expanduser()
        if not file.exists():
            raise ValueError(f"{file} does not exist")
        if not file.is_file():
            raise ValueError(f"{file} is not a file")
        return file

    try:
        validate_ssh_pubkey_file(ssh_pubkey_file)
    except ValueError:
        ssh_pubkey_file = Path(
            validated_prompt(
                f"{ssh_pubkey_file} does not exist. Please enter a path to a public ssh key to be added to the instance.",
                validate_ssh_pubkey_file,
            )
        )

    ssh_pubkey = load_ssh_pubkey(ssh_pubkey_file)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    rootfs = (
        rootfs
        or input(
            f"Aleph ID of root volume (rootfs)? [default: {settings.DEFAULT_ROOTFS_ID}] "
        )
        or settings.DEFAULT_ROOTFS_ID
    )

    async with AlephHttpClient(api_server=sdk_settings.API_HOST) as client:
        rootfs_message: StoreMessage = await client.get_message(
            item_hash=rootfs, message_type=StoreMessage
        )
        if not rootfs_message:
            typer.echo("Given rootfs volume does not exist on aleph.im")
            raise typer.Exit(code=1)
        rootfs_size = rootfs_message.content.size
        if rootfs_name is None and rootfs_message.content.metadata:
            rootfs_name = rootfs_message.content.metadata.get("name", None)
        if rootfs_size is None and rootfs_message.content.size:
            rootfs_size = rootfs_message.content.size

    rootfs_name = (
        rootfs_name
        or input(f"Name of root volume? [default: {settings.DEFAULT_ROOTFS_NAME}] ")
        or settings.DEFAULT_ROOTFS_NAME
    )

    rootfs_size = (
        rootfs_size
        or input(f"Size in MiB ? [{settings.DEFAULT_ROOTFS_SIZE}] ")
        or settings.DEFAULT_ROOTFS_SIZE
    )

    volumes = get_or_prompt_volumes(
        persistent_volume=persistent_volume,
        ephemeral_volume=ephemeral_volume,
        immutable_volume=immutable_volume,
    )

    async with AuthenticatedAlephHttpClient(
        account=account, api_server=sdk_settings.API_HOST
    ) as client:
        # Register the instance
        message, status = await client.create_instance(
            sync=True,
            rootfs=rootfs,
            rootfs_size=rootfs_size,
            rootfs_name=rootfs_name,
            storage_engine=StorageEnum.storage,
            channel=channel,
            memory=memory,
            vcpus=vcpus,
            timeout_seconds=timeout_seconds,
            volumes=volumes,
            ssh_keys=[ssh_pubkey],
        )
        if print_messages:
            typer.echo(f"{message.json(indent=4)}")

        item_hash: ItemHash = message.item_hash
        hash_base32 = (
            b32encode(b16decode(item_hash.upper())).strip(b"=").lower().decode()
        )

        typer.echo(
            f"\nYour instance has been deployed on aleph.im\n\n"
            f"Your SSH key has been added to the instance. You can connect in a few minutes to it using:\n"
            # TODO: Resolve to IPv6 address
            f"  ssh -i {ssh_pubkey_file} root@{hash_base32}.aleph.sh\n\n"
            "Also available on:\n"
            f"  {settings.VM_URL_PATH.format(hash=item_hash)}\n"
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
