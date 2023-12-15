import asyncio
import logging
from base64 import b16decode, b32encode
from pathlib import Path
from typing import List, Optional, Tuple, Union

import typer
from aiohttp import ClientResponseError, ClientSession
from aleph.sdk import AlephHttpClient, AuthenticatedAlephHttpClient
from aleph.sdk.account import _load_account
from aleph.sdk.conf import settings as sdk_settings
from aleph.sdk.exceptions import (
    ForgottenMessageError,
    InsufficientFundsError,
    MessageNotFoundError,
)
from aleph.sdk.query.filters import MessageFilter
from aleph.sdk.types import AccountFromPrivateKey, StorageEnum
from aleph_message.models import InstanceMessage, ItemHash, MessageType, StoreMessage
from rich import box
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from aleph_client.commands import help_strings
from aleph_client.commands.utils import (
    get_or_prompt_volumes,
    setup_logging,
    validated_int_prompt,
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
        "Ubuntu 22",
        help="Hash of the rootfs to use for your instance. Defaults to Ubuntu 22. You can also create your own rootfs and pin it",
    ),
    rootfs_name: str = typer.Option(
        settings.DEFAULT_ROOTFS_NAME,
        help="Name of the rootfs to use for your instance. If not set, content.metadata.name of the --rootfs store message will be used.",
    ),
    rootfs_size: int = typer.Option(
        settings.DEFAULT_ROOTFS_SIZE,
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
        ssh_pubkey_file = validate_ssh_pubkey_file(ssh_pubkey_file)
    except ValueError:
        ssh_pubkey_file = Path(
            validated_prompt(
                f"{ssh_pubkey_file} does not exist. Please enter a path to a public ssh key to be added to the instance.",
                validate_ssh_pubkey_file,
            )
        )

    ssh_pubkey = load_ssh_pubkey(ssh_pubkey_file)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    os_map = {
        settings.UBUNTU_22_ROOTFS_ID: "Ubuntu 22",
        settings.DEBIAN_12_ROOTFS_ID: "Debian 12",
        settings.DEBIAN_11_ROOTFS_ID: "Debian 11",
    }

    rootfs = Prompt.ask(
        f"Do you want to use a custom rootfs or one of the following prebuilt ones?",
        default=rootfs,
        choices=[*os_map.values(), "custom"],
    )

    if rootfs == "custom":
        rootfs = validated_prompt(
            f"Enter the item hash of the rootfs to use for your instance",
            lambda x: len(x) == 64,
        )
    else:
        rootfs = next(k for k, v in os_map.items() if v == rootfs)

    async with AlephHttpClient(api_server=sdk_settings.API_HOST) as client:
        rootfs_message: StoreMessage = await client.get_message(
            item_hash=rootfs, message_type=StoreMessage
        )
        if not rootfs_message:
            typer.echo("Given rootfs volume does not exist on aleph.im")
            raise typer.Exit(code=1)
        if rootfs_name is None and rootfs_message.content.metadata:
            rootfs_name = rootfs_message.content.metadata.get("name", None)
        if rootfs_size is None and rootfs_message.content.size:
            rootfs_size = rootfs_message.content.size

    rootfs_name = Prompt.ask(
        f"Name of the rootfs to use for your instance",
        default=os_map.get(rootfs, rootfs_name),
    )

    vcpus = validated_int_prompt(
        f"Number of virtual cpus to allocate", vcpus, min_value=1, max_value=4
    )

    memory = validated_int_prompt(
        f"Maximum memory allocation on vm in MiB", memory, min_value=256, max_value=8000
    )

    rootfs_size = validated_int_prompt(
        f"Disk size in MiB", rootfs_size, min_value=2000, max_value=100000
    )

    volumes = get_or_prompt_volumes(
        persistent_volume=persistent_volume,
        ephemeral_volume=ephemeral_volume,
        immutable_volume=immutable_volume,
    )

    async with AuthenticatedAlephHttpClient(
        account=account, api_server=sdk_settings.API_HOST
    ) as client:
        try:
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
        except InsufficientFundsError as e:
            typer.echo(
                f"Instance creation failed due to insufficient funds.\n"
                f"{account.get_address()} on {account.CHAIN} has {e.available_funds} ALEPH but needs {e.required_funds} ALEPH."
            )
            raise typer.Exit(code=1)
        if print_messages:
            typer.echo(f"{message.json(indent=4)}")

        item_hash: ItemHash = message.item_hash

        console = Console()
        console.print(
            f"\nYour instance {item_hash} has been deployed on aleph.im\n"
            f"Your SSH key has been added to the instance. You can connect in a few minutes to it using:\n\n"
            f"  ssh root@<ipv6 address>\n\n"
            f"Run the following command to get the IPv6 address of your instance:\n\n"
            f"  aleph instance list\n\n"
        )


@app.command()
async def delete(
    item_hash: str,
    reason: str = typer.Option(
        "User deletion", help="Reason for deleting the instance"
    ),
    private_key: Optional[str] = sdk_settings.PRIVATE_KEY_STRING,
    private_key_file: Optional[Path] = sdk_settings.PRIVATE_KEY_FILE,
    print_message: bool = typer.Option(False),
    debug: bool = False,
):
    """Delete an instance, unallocating all resources associated with it. Immutable volumes will not be deleted."""

    setup_logging(debug)

    account = _load_account(private_key, private_key_file)

    async with AuthenticatedAlephHttpClient(
        account=account, api_server=sdk_settings.API_HOST
    ) as client:
        try:
            existing_message: InstanceMessage = await client.get_message(
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

        message, status = await client.forget(hashes=[item_hash], reason=reason)
        if print_message:
            typer.echo(f"{message.json(indent=4)}")

        typer.echo(
            f"Instance {item_hash} has been deleted. It will be removed by the scheduler in a few minutes."
        )


async def _get_ipv6_address(message: InstanceMessage) -> Tuple[str, str]:
    async with ClientSession() as session:
        try:
            resp = await session.get(
                f"https://scheduler.api.aleph.cloud/api/v0/allocation/{message.item_hash}"
            )
            resp.raise_for_status()
            status = await resp.json()
            return status["vm_hash"], status["vm_ipv6"]
        except ClientResponseError:
            return message.item_hash, "Not available (yet)"


async def _show_instances(messages: List[InstanceMessage]):
    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("Item Hash", style="cyan")
    table.add_column("Vcpus", style="magenta")
    table.add_column("Memory", style="magenta")
    table.add_column("Disk size", style="magenta")
    table.add_column("IPv6 address", style="yellow")

    scheduler_responses = dict(
        await asyncio.gather(*[_get_ipv6_address(message) for message in messages])
    )

    for message in messages:
        table.add_row(
            message.item_hash,
            str(message.content.resources.vcpus),
            str(message.content.resources.memory),
            str(message.content.rootfs.size_mib),
            scheduler_responses[message.item_hash],
        )
    console = Console()
    console.print(table)
    console.print(f"To connect to an instance, use:\n\n" f"  ssh root@<ipv6 address>\n")


@app.command()
async def list(
    address: Optional[str] = typer.Option(None, help="Owner address of the instance"),
    private_key: Optional[str] = typer.Option(
        sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY
    ),
    private_key_file: Optional[Path] = typer.Option(
        sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE
    ),
    json: bool = typer.Option(
        default=False, help="Print as json instead of rich table"
    ),
    debug: bool = False,
):
    """List all instances associated with your private key"""

    setup_logging(debug)

    if address is None:
        account = _load_account(private_key, private_key_file)
        address = account.get_address()

    async with AlephHttpClient(api_server=sdk_settings.API_HOST) as client:
        resp = await client.get_messages(
            message_filter=MessageFilter(
                message_types=[MessageType.instance],
                addresses=[address],
            ),
            page_size=100,
        )
        if not resp:
            typer.echo("No instances found")
            raise typer.Exit(code=1)
        if json:
            typer.echo(resp.json(indent=4))
        else:
            await _show_instances(resp.messages)
