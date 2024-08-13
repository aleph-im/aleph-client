from __future__ import annotations

import asyncio
import json
import logging
import shutil
from decimal import Decimal

# from aleph.sdk.query.responses import PriceResponse // This should be uncomment when https://github.com/aleph-im/aleph-sdk-python/pull/143 is merge
from pathlib import Path
from typing import List, Optional, Tuple, Union, cast

import typer
from aiohttp import ClientResponseError, ClientSession
from aleph.sdk import AlephHttpClient, AuthenticatedAlephHttpClient
from aleph.sdk.account import _load_account
from aleph.sdk.client.superfluid import SuperFluid
from aleph.sdk.client.vm_client import VmClient
from aleph.sdk.client.vm_confidential_client import VmConfidentialClient
from aleph.sdk.conf import settings as sdk_settings
from aleph.sdk.exceptions import (
    ForgottenMessageError,
    InsufficientFundsError,
    MessageNotFoundError,
)
from aleph.sdk.query.filters import MessageFilter
from aleph.sdk.types import AccountFromPrivateKey, StorageEnum
from aleph.sdk.utils import calculate_firmware_hash
from aleph_message.models import InstanceMessage, StoreMessage
from aleph_message.models.base import Chain, MessageType
from aleph_message.models.execution.base import Payment, PaymentType
from aleph_message.models.execution.environment import (
    HostRequirements,
    HypervisorType,
    NodeRequirements,
    TrustedExecutionEnvironment,
)
from aleph_message.models.item_hash import ItemHash
from click import echo
from rich import box
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table

from aleph_client.commands import help_strings
from aleph_client.commands.instance.display import CRNInfo, CRNTable
from aleph_client.commands.instance.superfluid import handle_flow, handle_flow_reduction
from aleph_client.commands.node import NodeInfo, _fetch_nodes
from aleph_client.commands.utils import (
    get_or_prompt_volumes,
    setup_logging,
    validated_int_prompt,
    validated_prompt,
)
from aleph_client.conf import settings
from aleph_client.models import MachineUsage
from aleph_client.utils import AsyncTyper, fetch_json

logger = logging.getLogger(__name__)
app = AsyncTyper(no_args_is_help=True)


@app.command()
async def create(
    hold: bool = typer.Option(
        default=False,
        help="Pay using the holder tier instead of pay-as-you-go",
    ),
    channel: Optional[str] = typer.Option(default=None, help=help_strings.CHANNEL),
    confidential: Optional[bool] = typer.Option(default=None, help=help_strings.CONFIDENTIAL_OPTION),
    confidential_firmware: str = typer.Option(
        default=settings.DEFAULT_CONFIDENTIAL_FIRMWARE, help=help_strings.CONFIDENTIAL_FIRMWARE
    ),
    memory: int = typer.Option(settings.DEFAULT_INSTANCE_MEMORY, help="Maximum memory allocation on vm in MiB"),
    vcpus: int = typer.Option(sdk_settings.DEFAULT_VM_VCPUS, help="Number of virtual cpus to allocate."),
    timeout_seconds: float = typer.Option(
        sdk_settings.DEFAULT_VM_TIMEOUT,
        help="If vm is not called after [timeout_seconds] it will shutdown",
    ),
    private_key: Optional[str] = typer.Option(sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    ssh_pubkey_file: Path = typer.Option(
        Path("~/.ssh/id_rsa.pub").expanduser(),
        help="Path to a public ssh key to be added to the instance.",
    ),
    print_messages: bool = typer.Option(False),
    rootfs: str = typer.Option(
        "Ubuntu 22",
        help="Hash of the rootfs to use for your instance. Defaults to Ubuntu 22. You can also create your own rootfs and pin it",
    ),
    rootfs_size: int = typer.Option(
        settings.DEFAULT_ROOTFS_SIZE,
        help="Size of the rootfs to use for your instance. If not set, content.size of the --rootfs store message will be used.",
    ),
    hypervisor: HypervisorType = typer.Option(
        default=None,
        help="Hypervisor to use to launch your instance. Defaults to Firecracker.",
    ),
    debug: bool = False,
    persistent_volume: Optional[List[str]] = typer.Option(None, help=help_strings.PERSISTENT_VOLUME),
    ephemeral_volume: Optional[List[str]] = typer.Option(None, help=help_strings.EPHEMERAL_VOLUME),
    immutable_volume: Optional[List[str]] = typer.Option(
        None,
        help=help_strings.IMMUATABLE_VOLUME,
    ),
    crn_url=typer.Option(None, help=help_strings.CRN_URL),
    crn_hash=typer.Option(None, help=help_strings.CRN_HASH),
    stream_reward=typer.Option(None, help="stream reward Node hash"),
    sync_cloud: Optional[bool] = typer.Option(True, help=help_strings.SYNC_CLOUD),
    instance_name: Optional[str] = typer.Option(None, help=help_strings.INSTANCE_NAME),
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

    ssh_pubkey: str = ssh_pubkey_file.read_text().strip()

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    if confidential:
        if hypervisor and hypervisor != HypervisorType.qemu:
            echo(f"Only QEMU is supported as an hypervisor for confidential")
            raise typer.Exit(code=1)
        elif not hypervisor:
            echo(f"Using QEMU as hypervisor for confidential")
            hypervisor = HypervisorType.qemu

    available_hypervisors = {
        HypervisorType.firecracker: {
            "Ubuntu 22": settings.UBUNTU_22_ROOTFS_ID,
            "Debian 12": settings.DEBIAN_12_ROOTFS_ID,
            "Debian 11": settings.DEBIAN_11_ROOTFS_ID,
        },
        HypervisorType.qemu: {
            "Ubuntu 22": settings.UBUNTU_22_QEMU_ROOTFS_ID,
            "Debian 12": settings.DEBIAN_12_QEMU_ROOTFS_ID,
            "Debian 11": settings.DEBIAN_11_QEMU_ROOTFS_ID,
        },
    }

    if hypervisor is None:
        hypervisor_choice = HypervisorType[
            Prompt.ask(
                "Which hypervisor you want to use?",
                default=settings.DEFAULT_HYPERVISOR.name,
                choices=[x.name for x in available_hypervisors],
            )
        ]
        hypervisor = HypervisorType(hypervisor_choice)

    os_choices = available_hypervisors[hypervisor]

    if confidential:
        # Confidential only support custom rootfs
        rootfs = "custom"
    else:
        rootfs = Prompt.ask(
            "Do you want to use a custom rootfs or one of the following prebuilt ones?",
            default=rootfs,
            choices=[*os_choices, "custom"],
        )

    if rootfs == "custom":
        rootfs = validated_prompt(
            "Enter the item hash of the rootfs to use for your instance",
            lambda x: len(x) == 64,
        )
    else:
        rootfs = os_choices[rootfs]

    if sync_cloud:
        instance_name = Prompt.ask(
            "How do you want to call your instance ?",
        )

    # Validate rootfs message exist
    async with AlephHttpClient(api_server=sdk_settings.API_HOST) as client:
        rootfs_message: StoreMessage = await client.get_message(item_hash=rootfs, message_type=StoreMessage)
        if not rootfs_message:
            typer.echo("Given rootfs volume does not exist on aleph.im")
            raise typer.Exit(code=1)
        if rootfs_size is None and rootfs_message.content.size:
            rootfs_size = rootfs_message.content.size

    # Validate confidential firmware message exist
    confidential_firmware_as_hash = None
    if confidential:
        async with AlephHttpClient(api_server=sdk_settings.API_HOST) as client:

            confidential_firmware_as_hash = ItemHash(confidential_firmware)
            firmware_message: StoreMessage = await client.get_message(
                item_hash=confidential_firmware, message_type=StoreMessage
            )
            if not firmware_message:
                typer.echo("Confidential Firmware hash does not exist on aleph.im")
                raise typer.Exit(code=1)

    vcpus = validated_int_prompt("Number of virtual cpus to allocate", vcpus, min_value=1, max_value=4)

    memory = validated_int_prompt("Maximum memory allocation on vm in MiB", memory, min_value=2000, max_value=8000)

    rootfs_size = validated_int_prompt("Disk size in MiB", rootfs_size, min_value=20000, max_value=100000)

    volumes = get_or_prompt_volumes(
        persistent_volume=persistent_volume,
        ephemeral_volume=ephemeral_volume,
        immutable_volume=immutable_volume,
    )

    crn = None
    if crn_url and crn_hash:
        crn = CRNInfo(
            url=crn_url,
            hash=crn_hash,
            score=10,
            name="",
            stream_reward=stream_reward,
            machine_usage=None,
            version=None,
            confidential_computing=None,
        )
    if not hold or confidential:
        while not crn:
            crn_table = CRNTable()
            crn = await crn_table.run_async()
            if not crn:
                # User has ctrl-c
                return
            print("Run instance on CRN:")
            print("\t Name", crn.name)
            print("\t Stream address", crn.stream_reward)
            print("\t URL", crn.url)
            if isinstance(crn.machine_usage, MachineUsage):
                print("\t Available disk space", crn.machine_usage.disk)
                print("\t Available ram", crn.machine_usage.mem)
            if not Confirm.ask("Deploy on this node ?"):
                crn = None
                continue
            stream_reward = crn.stream_reward

    async with AuthenticatedAlephHttpClient(account=account, api_server=sdk_settings.API_HOST) as client:
        payment: Optional[Payment] = None
        if stream_reward:
            payment = Payment(
                chain=Chain.AVAX,
                receiver=stream_reward,
                type=PaymentType["superfluid"],
            )
        try:
            message, status = await client.create_instance(
                sync=True,
                rootfs=rootfs,
                rootfs_size=rootfs_size,
                storage_engine=StorageEnum.storage,
                channel=channel if not sync_cloud else settings.CLOUD_CHANNEL,
                metadata={"name": instance_name} if sync_cloud else None,
                memory=memory,
                vcpus=vcpus,
                timeout_seconds=timeout_seconds,
                volumes=volumes,
                ssh_keys=[ssh_pubkey],
                payment=payment,
                hypervisor=hypervisor,
                requirements=HostRequirements(node=NodeRequirements(node_hash=crn.hash)) if crn else None,
                trusted_execution=(
                    TrustedExecutionEnvironment(firmware=confidential_firmware_as_hash) if confidential else None
                ),
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
        if crn and (confidential or not hold):
            if not crn.url:
                return
            # price: PriceResponse = await client.get_program_price(item_hash) // https://github.com/aleph-im/aleph-sdk-python/pull/143
            price = "0.000003555555555555"  # This value work only because right now PriceCalculations is bug on this release (patch already in pyaleph)

            # We load SuperFluid account
            superfluid_client = _load_account(private_key, private_key_file, account_type=SuperFluid)

            flow_hash = await handle_flow(
                account=superfluid_client,
                sender=account.get_address(),
                receiver=crn.stream_reward,
                flow=Decimal(price),  # should be price.required_token (cause it's should be a PriceResponse)
            )
            typer.echo(f"Flow {flow_hash} has been created of {price}")

            async with AuthenticatedAlephHttpClient(account=account, api_server=sdk_settings.API_HOST) as client:
                account = _load_account(private_key, private_key_file)
                async with VmClient(account, crn.url) as crn_client:
                    while True:
                        try:
                            status, result = await crn_client.start_instance(vm_id=item_hash)
                            logger.debug(f"Crn : {crn.url} Status: {status}, Result: {result}")
                            if int(status) == 200:
                                if not confidential:
                                    console.print(
                                        f"\nYour instance {item_hash} has been deployed on aleph.im\n"
                                        f"Your SSH key has been added to the instance. You can connect in a few minutes to it using:\n\n"
                                        f"  ssh root@<ipv6 address>\n\n"
                                        f"Run the following command to get the IPv6 address of your instance:\n\n"
                                        f"  aleph instance list\n\n"
                                    )
                                else:
                                    console.print(
                                        f"\nYour instance {item_hash} has been deployed on aleph.im\n"
                                        f"Initialize a confidential session using :\n\n"
                                        f"  aleph instance confidential-init-session {item_hash} {crn.url}\n\n"
                                        f"Then start it using :\n\n"
                                        f"  aleph instance confidential-start {item_hash} {crn.url}\n\n"
                                    )
                                return
                            else:
                                print(f"Failed to start instance {crn.url} {item_hash}, status: {status}. Retrying...")
                        except Exception as e:
                            logger.error(f"Error starting instance {item_hash}: {e}")

                        logger.debug(f"Retrying in {10} seconds...")
                        await asyncio.sleep(10)


@app.command()
async def delete(
    item_hash: str,
    reason: str = typer.Option("User deletion", help="Reason for deleting the instance"),
    private_key: Optional[str] = sdk_settings.PRIVATE_KEY_STRING,
    private_key_file: Optional[Path] = sdk_settings.PRIVATE_KEY_FILE,
    print_message: bool = typer.Option(False),
    debug: bool = False,
):
    """Delete an instance, unallocating all resources associated with it. Immutable volumes will not be deleted."""

    setup_logging(debug)

    account = _load_account(private_key, private_key_file)

    async with AuthenticatedAlephHttpClient(account=account, api_server=sdk_settings.API_HOST) as client:
        try:
            existing_message: InstanceMessage = await client.get_message(
                item_hash=ItemHash(item_hash), message_type=InstanceMessage
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

        payment: Optional[Payment] = existing_message.content.payment

        if payment is not None and payment.type == PaymentType.superfluid:
            # price: PriceResponse = await client.get_program_price(item_hash)
            flow = "0.000003555555555555"
            superfluid_client = _load_account(private_key, private_key_file, account_type=SuperFluid)

            # Check if payment.receiver is not None
            if payment.receiver is not None:
                flow_hash = await handle_flow_reduction(
                    superfluid_client,
                    existing_message.sender,
                    payment.receiver,
                    Decimal(flow),  # should be replaced with price
                )

        message, status = await client.forget(hashes=[ItemHash(item_hash)], reason=reason)
        if print_message:
            typer.echo(f"{message.json(indent=4)}")

        typer.echo(f"Instance {item_hash} has been deleted. It will be removed by the scheduler in a few minutes.")


async def _get_ipv6_address(message: InstanceMessage, node_list: NodeInfo) -> Tuple[str, str]:
    async with ClientSession() as session:
        try:
            if not message.content.payment:
                # Fetch from the scheduler API directly if no payment
                status = await fetch_json(
                    session,
                    f"https://scheduler.api.aleph.cloud/api/v0/allocation/{message.item_hash}",
                )
                return status["vm_hash"], status["vm_ipv6"]
            for node in node_list.nodes:
                if node["stream_reward"] == message.content.payment.receiver:

                    # Handle both cases where the address might or might not end with a '/'
                    path: str = (
                        f"{node['address']}about/executions/list"
                        if node["address"][-1] == "/"
                        else f"{node['address']}/about/executions/list"
                    )
                    # Fetch from the CRN API if payment
                    executions = await fetch_json(session, path)
                    if message.item_hash in executions:
                        ipv6_address = executions[message.item_hash]["networking"]["ipv6"]
                        return message.item_hash, ipv6_address

            return message.item_hash, "Not available (yet)"
        except ClientResponseError as e:
            return message.item_hash, f"Not available (yet), server not responding : {e}"


async def _show_instances(messages: List[InstanceMessage], node_list: NodeInfo):
    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column("Item Hash", style="cyan")
    table.add_column("Vcpus", style="magenta")
    table.add_column("Memory", style="magenta")
    table.add_column("Disk size", style="magenta")
    table.add_column("IPv6 address", style="yellow")

    scheduler_responses = dict(await asyncio.gather(*[_get_ipv6_address(message, node_list) for message in messages]))

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
    console.print("To connect to an instance, use:\n\n" "  ssh root@<ipv6 address>\n")


@app.command()
async def list(
    address: Optional[str] = typer.Option(None, help="Owner address of the instance"),
    private_key: Optional[str] = typer.Option(sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    json: bool = typer.Option(default=False, help="Print as json instead of rich table"),
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
            # Since we filtered on message type, we can safely cast as InstanceMessage.
            messages = cast(List[InstanceMessage], resp.messages)
            resource_nodes: NodeInfo = await _fetch_nodes()
            await _show_instances(messages, resource_nodes)


@app.command()
async def expire(
    vm_id: str,
    domain: str,
    private_key: Optional[str] = typer.Option(sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    """expire an instance"""

    setup_logging(debug)
    account = _load_account(private_key, private_key_file)

    async with VmClient(account, domain) as manager:
        status, result = await manager.expire_instance(vm_id=vm_id)
        if status != 200:
            typer.echo(f"Status : {status}")
        typer.echo(result)


@app.command()
async def erase(
    vm_id: str,
    domain: str,
    private_key: Optional[str] = typer.Option(sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    """erase an instance"""

    setup_logging(debug)

    account = _load_account(private_key, private_key_file)

    async with VmClient(account, domain) as manager:
        status, result = await manager.erase_instance(vm_id=vm_id)
        if status != 200:
            typer.echo(f"Status : {status}")
        typer.echo(result)


@app.command()
async def reboot(
    vm_id: str,
    domain: str,
    private_key: Optional[str] = typer.Option(sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    """reboot an instance"""

    setup_logging(debug)

    account = _load_account(private_key, private_key_file)

    async with VmClient(account, domain) as manager:
        status, result = await manager.reboot_instance(vm_id=vm_id)
        if status != 200:
            typer.echo(f"Status : {status}")
        typer.echo(result)


@app.command()
async def allocate(
    vm_id: str,
    domain: str,
    private_key: Optional[str] = typer.Option(sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    """Tell the CRN to start an instance with Pay as you go"""

    setup_logging(debug)

    account = _load_account(private_key, private_key_file)

    async with VmClient(account, domain) as manager:
        status, result = await manager.start_instance(vm_id=vm_id)
        if status != 200:
            typer.echo(f"Status : {status}")
        typer.echo(result)


@app.command()
async def logs(
    vm_id: str,
    domain: str,
    private_key: Optional[str] = typer.Option(sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    """logs of the instance"""
    setup_logging(debug)

    account = _load_account(private_key, private_key_file)

    async with VmClient(account, domain) as manager:
        async for log in manager.get_logs(vm_id=vm_id):
            log_data = json.loads(log)
            if "message" in log_data:
                typer.echo(log_data["message"])


@app.command()
async def stop(
    vm_id: str,
    domain: str,
    private_key: Optional[str] = typer.Option(sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    """Stop an instance"""

    setup_logging(debug)

    account = _load_account(private_key, private_key_file)

    async with VmClient(account, domain) as manager:
        status, result = await manager.stop_instance(vm_id=vm_id)
        if status != 200:
            typer.echo(f"Status : {status}")
        typer.echo(result)


@app.command()
async def confidential_init_session(
    vm_id: str,
    domain: str,
    policy: int = typer.Option(default=0x1),
    private_key: Optional[str] = typer.Option(sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    "Initialize a confidential communication session wit the VM"
    assert settings.CONFIG_HOME

    session_dir = Path(settings.CONFIG_HOME) / "confidential_sessions" / vm_id
    session_dir.mkdir(exist_ok=True, parents=True)

    setup_logging(debug)
    account = _load_account(private_key, private_key_file)

    sevctl_path = shutil.which("sevctl")
    if sevctl_path is None:
        echo("sevctl is not available. Please install sevctl, ensure it is in the PATH and try again.")
        return

    if (session_dir / "vm_godh.b64").exists():
        if not Confirm.ask(
            "Session already initiated for this instance, are you sure you want to override the previous one? You won't be able to communicate with already running vm"
        ):
            return

    client = VmConfidentialClient(account, Path(sevctl_path), domain)

    code, platform_file = await client.get_certificates()
    if code != 200:
        echo("Could not get the certificate from the CRN.")
        return

    platform_cert_path = Path(platform_file).rename(session_dir / "platform_certificate.pem")
    certificate_prefix = str(session_dir) + "/vm"

    # Create local session files
    await client.create_session(certificate_prefix, certificate_path=platform_cert_path, policy=policy)  # type:ignore
    # TOFIX in sdk Create session should take a string and not an item hash

    logger.info(f"Certificate created in {platform_cert_path}")

    godh_path = session_dir / "vm_godh.b64"
    session_path = session_dir / "vm_session.b64"
    assert godh_path.exists()

    vm_hash = ItemHash(vm_id)

    await client.initialize(vm_hash, session_path, godh_path)
    echo("Confidential Session with VM and CRN initiated")
    await client.close()


@app.command()
async def confidential_start(
    vm_id: str,
    domain: str,
    policy: int = typer.Option(default=0x1),
    firmware_hash: str = typer.Option(
        settings.DEFAULT_CONFIDENTIAL_FIRMWARE_HASH, help=help_strings.CONFIDENTIAL_FIRMWARE_HASH
    ),
    firmware_file: str = typer.Option(default=None, help=help_strings.PRIVATE_KEY),
    private_key: Optional[str] = typer.Option(sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    "Validate the authenticity of the VM and start it"
    assert settings.CONFIG_HOME
    session_dir = Path(settings.CONFIG_HOME) / "confidential_sessions" / vm_id
    session_dir.mkdir(exist_ok=True, parents=True)

    setup_logging(debug)
    account = _load_account(private_key, private_key_file)

    sevctl_path = shutil.which("sevctl")
    if sevctl_path is None:
        echo("sevctl is not available. Please install sevctl, ensure it is in the PATH and try again.")
        return

    client = VmConfidentialClient(account, Path(sevctl_path), domain)

    bytes.fromhex(firmware_hash)

    vm_hash = ItemHash(vm_id)

    if not session_dir.exists():
        echo("Please run confidential-init-session first ")
        return 1

    sev_data = await client.measurement(vm_hash)
    echo("Retrieved measurement")

    tek_path = session_dir / "vm_tek.bin"
    tik_path = session_dir / "vm_tik.bin"

    if firmware_file:
        firmware_path = Path(firmware_file)
        if not firmware_path.exists():
            raise Exception("Firmware path does not exist")
        firmware_hash = calculate_firmware_hash(firmware_path)
        logger.info(f"Calculated Firmware hash: {firmware_hash}")
    logger.info(sev_data)
    valid = await client.validate_measure(sev_data, tik_path, firmware_hash=firmware_hash)
    if not valid:
        echo("Could not validate authenticity of the VM. Please check that you are validating against the proper hash")
        return 2
    echo("Measurement are authentic")

    secret_key = Prompt.ask(
        "Please enter secret to start the VM",
    )

    encoded_packet_header, encoded_secret = await client.build_secret(tek_path, tik_path, sev_data, secret_key)
    await client.inject_secret(vm_hash, encoded_packet_header, encoded_secret)
    echo("Starting the instance...")
    echo("Logs can be fetched using the `aleph instance logs` command")
    echo("Run the following command to get the IPv6 address of your instance:  aleph instance list")
    await client.close()
