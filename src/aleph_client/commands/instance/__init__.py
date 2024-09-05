from __future__ import annotations

import asyncio
import json
import logging
import shutil
from decimal import Decimal
from math import ceil
from pathlib import Path
from typing import List, Optional, Tuple, Union, cast

import aiohttp
import typer
from aleph.sdk import AlephHttpClient, AuthenticatedAlephHttpClient
from aleph.sdk.account import _load_account
from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.client.vm_client import VmClient
from aleph.sdk.client.vm_confidential_client import VmConfidentialClient
from aleph.sdk.conf import settings
from aleph.sdk.evm_utils import get_chains_with_super_token
from aleph.sdk.exceptions import (
    ForgottenMessageError,
    InsufficientFundsError,
    MessageNotFoundError,
)
from aleph.sdk.query.filters import MessageFilter
from aleph.sdk.query.responses import PriceResponse
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
from rich.text import Text

from aleph_client.commands import help_strings
from aleph_client.commands.instance.display import CRNTable
from aleph_client.commands.instance.network import (
    fetch_crn_info,
    fetch_vm_info,
    find_crn_of_vm,
    sanitize_url,
)
from aleph_client.commands.instance.superfluid import FlowUpdate, update_flow
from aleph_client.commands.node import NodeInfo, _fetch_nodes
from aleph_client.commands.utils import (
    filter_only_valid_messages,
    get_or_prompt_volumes,
    safe_getattr,
    setup_logging,
    validated_int_prompt,
    validated_prompt,
    wait_for_confirmed_flow,
    wait_for_processed_instance,
)
from aleph_client.models import CRNInfo
from aleph_client.utils import AsyncTyper

logger = logging.getLogger(__name__)
app = AsyncTyper(no_args_is_help=True)


@app.command()
async def create(
    payment_type: Optional[str] = typer.Option(
        None,
        help=help_strings.PAYMENT_TYPE,
        callback=lambda pt: None if pt is None else PaymentType.hold if pt == "nft" else PaymentType(pt),
        metavar=f"[{'|'.join(PaymentType)}|nft]",
    ),
    payment_chain: Optional[Chain] = typer.Option(
        None, help=help_strings.PAYMENT_CHAIN, metavar=f"[{'|'.join([Chain.ETH, Chain.AVAX, Chain.BASE])}]"
    ),
    hypervisor: Optional[HypervisorType] = typer.Option(None, help=help_strings.HYPERVISOR),
    name: Optional[str] = typer.Option(None, help=help_strings.INSTANCE_NAME),
    rootfs: Optional[str] = typer.Option(None, help=help_strings.ROOTFS),
    rootfs_size: Optional[int] = typer.Option(None, help=help_strings.ROOTFS_SIZE),
    vcpus: Optional[int] = typer.Option(None, help=help_strings.VCPUS),
    memory: Optional[int] = typer.Option(None, help=help_strings.MEMORY),
    timeout_seconds: float = typer.Option(
        settings.DEFAULT_VM_TIMEOUT,
        help=help_strings.TIMEOUT_SECONDS,
    ),
    ssh_pubkey_file: Path = typer.Option(
        Path("~/.ssh/id_rsa.pub").expanduser(),
        help=help_strings.SSH_PUBKEY_FILE,
    ),
    crn_hash: Optional[str] = typer.Option(None, help=help_strings.CRN_HASH),
    crn_url: Optional[str] = typer.Option(None, help=help_strings.CRN_URL),
    confidential: bool = typer.Option(False, help=help_strings.CONFIDENTIAL_OPTION),
    confidential_firmware: str = typer.Option(
        default=settings.DEFAULT_CONFIDENTIAL_FIRMWARE, help=help_strings.CONFIDENTIAL_FIRMWARE
    ),
    skip_volume: bool = typer.Option(False, help=help_strings.SKIP_VOLUME),
    persistent_volume: Optional[List[str]] = typer.Option(None, help=help_strings.PERSISTENT_VOLUME),
    ephemeral_volume: Optional[List[str]] = typer.Option(None, help=help_strings.EPHEMERAL_VOLUME),
    immutable_volume: Optional[List[str]] = typer.Option(
        None,
        help=help_strings.IMMUTABLE_VOLUME,
    ),
    channel: Optional[str] = typer.Option(default=settings.DEFAULT_CHANNEL, help=help_strings.CHANNEL),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    print_messages: bool = typer.Option(False),
    verbose: bool = typer.Option(True),
    debug: bool = False,
) -> Tuple[ItemHash, Optional[str]]:
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

    if payment_type is None:
        payment_type = Prompt.ask(
            "Which payment type do you want to use?",
            choices=[ptype.value for ptype in PaymentType] + ["nft"],
            default=PaymentType.superfluid.value,
        )
    payment_type = PaymentType.hold if payment_type == "nft" else PaymentType(payment_type)
    is_stream = payment_type != PaymentType.hold

    super_token_chains = get_chains_with_super_token()
    if is_stream:
        if payment_chain is None or payment_chain not in super_token_chains:
            payment_chain = Chain(
                Prompt.ask(
                    "Which chain do you want to use for Pay-As-You-Go?",
                    choices=super_token_chains,
                    default=Chain.AVAX.value,
                )
            )
        if isinstance(account, ETHAccount):
            account.switch_chain(payment_chain)
            if account.superfluid_connector:  # Quick check with theoretical min price
                try:
                    account.superfluid_connector.can_start_flow(Decimal(0.000031))  # 0.11/h
                except Exception as e:
                    echo(e)
                    raise typer.Exit(code=1)
    else:
        payment_chain = Chain.ETH  # Hold chain for all balances

    if confidential:
        if hypervisor and hypervisor != HypervisorType.qemu:
            echo("Only QEMU is supported as an hypervisor for confidential")
            raise typer.Exit(code=1)
        elif not hypervisor:
            echo("Using QEMU as hypervisor for confidential")
            hypervisor = HypervisorType.qemu

    available_hypervisors = {
        HypervisorType.firecracker: {
            "ubuntu22": settings.UBUNTU_22_ROOTFS_ID,
            "debian12": settings.DEBIAN_12_ROOTFS_ID,
            "debian11": settings.DEBIAN_11_ROOTFS_ID,
        },
        HypervisorType.qemu: {
            "ubuntu22": settings.UBUNTU_22_QEMU_ROOTFS_ID,
            "debian12": settings.DEBIAN_12_QEMU_ROOTFS_ID,
            "debian11": settings.DEBIAN_11_QEMU_ROOTFS_ID,
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
    is_qemu = hypervisor == HypervisorType.qemu

    os_choices = available_hypervisors[hypervisor]

    if not rootfs or len(rootfs) != 64:
        if confidential:
            # Confidential only support custom rootfs
            rootfs = "custom"
        elif not rootfs or rootfs not in os_choices:
            rootfs = Prompt.ask(
                "Use a custom rootfs or one of the following prebuilt ones:",
                default="ubuntu22",
                choices=[*os_choices, "custom"],
            )

        if rootfs == "custom":
            rootfs = validated_prompt(
                "Enter the item hash of the rootfs to use for your instance",
                lambda x: len(x) == 64,
            )
        else:
            rootfs = os_choices[rootfs]

    # Validate rootfs message exist
    async with AlephHttpClient(api_server=settings.API_HOST) as client:
        rootfs_message: StoreMessage = await client.get_message(item_hash=rootfs, message_type=StoreMessage)
        if not rootfs_message:
            echo("Given rootfs volume does not exist on aleph.im")
            raise typer.Exit(code=1)
        if rootfs_size is None and rootfs_message.content.size:
            rootfs_size = rootfs_message.content.size

    # Validate confidential firmware message exist
    confidential_firmware_as_hash = None
    if confidential:
        async with AlephHttpClient(api_server=settings.API_HOST) as client:
            confidential_firmware_as_hash = ItemHash(confidential_firmware)
            firmware_message: StoreMessage = await client.get_message(
                item_hash=confidential_firmware, message_type=StoreMessage
            )
            if not firmware_message:
                echo("Confidential Firmware hash does not exist on aleph.im")
                raise typer.Exit(code=1)

    name = name or validated_prompt("Instance name", lambda x: len(x) < 65)
    rootfs_size = rootfs_size or validated_int_prompt(
        "Disk size in MiB", default=settings.DEFAULT_ROOTFS_SIZE, min_value=10_240, max_value=102_400
    )
    vcpus = vcpus or validated_int_prompt(
        "Number of virtual cpus to allocate", default=settings.DEFAULT_VM_VCPUS, min_value=1, max_value=4
    )
    memory = memory or validated_int_prompt(
        "Maximum memory allocation on vm in MiB",
        default=settings.DEFAULT_INSTANCE_MEMORY,
        min_value=2_048,
        max_value=8_192,
    )

    volumes = []
    if not skip_volume:
        volumes = get_or_prompt_volumes(
            persistent_volume=persistent_volume,
            ephemeral_volume=ephemeral_volume,
            immutable_volume=immutable_volume,
        )

    stream_reward_address = None
    crn = None
    if crn_url and crn_hash:
        crn_url = sanitize_url(crn_url)
        try:
            crn_name, score, reward_addr = "?", 0, ""
            nodes: NodeInfo = await _fetch_nodes()
            for node in nodes.nodes:
                if node["address"].rstrip("/") == crn_url:
                    crn_name = node["name"]
                    score = node["score"]
                    reward_addr = node["stream_reward"]
                    break
            crn_info = await fetch_crn_info(crn_url)
            if crn_info:
                crn = CRNInfo(
                    hash=ItemHash(crn_hash),
                    name=crn_name or "?",
                    url=crn_url,
                    version=crn_info.get("version", ""),
                    score=score,
                    stream_reward_address=str(crn_info.get("payment", {}).get("PAYMENT_RECEIVER_ADDRESS"))
                    or reward_addr
                    or "",
                    machine_usage=crn_info.get("machine_usage"),
                    qemu_support=bool(crn_info.get("computing", {}).get("ENABLE_QEMU_SUPPORT", False)),
                    confidential_computing=bool(
                        crn_info.get("computing", {}).get("ENABLE_CONFIDENTIAL_COMPUTING", False)
                    ),
                )
                echo("\n* Selected CRN *")
                crn.display_crn_specs()
                echo()
        except Exception as e:
            echo(f"Unable to fetch CRN config: {e}")
            raise typer.Exit(1)
    if is_stream or confidential:
        while not crn:
            crn_table = CRNTable(only_reward_address=is_stream, only_qemu=is_qemu, only_confidentials=confidential)
            crn = await crn_table.run_async()
            if not crn:
                # User has ctrl-c
                raise typer.Exit(1)
            echo("\n* Selected CRN *")
            crn.display_crn_specs()
            if not Confirm.ask("\nDeploy on this node ?"):
                crn = None
                continue

    if crn:
        stream_reward_address = crn.stream_reward_address if hasattr(crn, "stream_reward_address") else ""
        if is_stream and not stream_reward_address:
            echo("Selected CRN does not have a defined receiver address.")
            raise typer.Exit(1)
        if is_qemu and (not hasattr(crn, "qemu_support") or not crn.qemu_support):
            echo("Selected CRN does not support QEMU hypervisor.")
            raise typer.Exit(1)
        if confidential and (not hasattr(crn, "confidential_computing") or not crn.confidential_computing):
            echo("Selected CRN does not support confidential computing.")
            raise typer.Exit(1)

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        payment = Payment(
            chain=payment_chain,
            receiver=stream_reward_address if stream_reward_address else None,
            type=payment_type,
        )
        try:
            message, status = await client.create_instance(
                sync=True,
                rootfs=rootfs,
                rootfs_size=rootfs_size,
                storage_engine=StorageEnum.storage,
                channel=channel,
                metadata={"name": name},
                memory=memory,
                vcpus=vcpus,
                timeout_seconds=timeout_seconds,
                volumes=volumes,
                ssh_keys=[ssh_pubkey],
                hypervisor=hypervisor,
                payment=payment,
                requirements=HostRequirements(node=NodeRequirements(node_hash=crn.hash)) if crn else None,
                trusted_execution=(
                    TrustedExecutionEnvironment(firmware=confidential_firmware_as_hash) if confidential else None
                ),
            )
        except InsufficientFundsError as e:
            echo(
                f"Instance creation failed due to insufficient funds.\n"
                f"{account.get_address()} on {account.CHAIN} has {e.available_funds} ALEPH but needs {e.required_funds} ALEPH."
            )
            raise typer.Exit(code=1)
        if print_messages:
            echo(f"{message.json(indent=4)}")

        item_hash: ItemHash = message.item_hash
        item_hash_text = Text(item_hash, style="bright_cyan")

        console = Console()

        # Instances that need to be started by notifying a specific CRN
        crn_url = crn.url if crn and crn.url else None
        if crn and (is_stream or confidential):
            if not crn_url:
                # Not the ideal solution
                logger.debug(f"Cannot allocate {item_hash}: no CRN url")
                return item_hash, crn_url

            # Wait for the instance message to be processed
            async with aiohttp.ClientSession() as session:
                await wait_for_processed_instance(session, item_hash)

            # Pay-As-You-Go
            if payment_type == PaymentType.superfluid:
                price: PriceResponse = await client.get_program_price(item_hash)
                ceil_factor = 10**18
                required_tokens = ceil(Decimal(price.required_tokens) * ceil_factor) / ceil_factor
                if isinstance(account, ETHAccount) and account.superfluid_connector:
                    try:  # Double check with effective price
                        account.superfluid_connector.can_start_flow(Decimal(0.000031))  # Min for 0.11/h
                    except Exception as e:
                        echo(e)
                        raise typer.Exit(code=1)
                    flow_hash = await update_flow(
                        account=account,
                        receiver=crn.stream_reward_address,
                        flow=Decimal(required_tokens),
                        update_type=FlowUpdate.INCREASE,
                    )
                    # Wait for the flow transaction to be confirmed
                    await wait_for_confirmed_flow(account, message.content.payment.receiver)
                    if flow_hash:
                        echo(
                            f"Flow {flow_hash} has been created:\n - Aleph cost summary:\n   {price.required_tokens:.7f}/sec | {3600*price.required_tokens:.2f}/hour | {86400*price.required_tokens:.2f}/day | {2592000*price.required_tokens:.2f}/month\n - CRN receiver address: {crn.stream_reward_address}"
                        )

            # Notify CRN
            async with VmClient(account, crn.url) as crn_client:
                status, result = await crn_client.start_instance(vm_id=item_hash)
                logger.debug(status, result)
                if int(status) != 200:
                    echo(f"Could not allocate instance {item_hash} on CRN.")
                    return item_hash, crn_url
            console.print(f"Your instance {item_hash_text} has been deployed on aleph.im.")
            if verbose:
                # PAYG-tier non-confidential instances
                if not confidential:
                    console.print(
                        "\n\nTo get the IPv6 address of the instance, check out:\n\n",
                        Text.assemble(
                            "  aleph instance list\n",
                            style="italic",
                        ),
                    )
                # All confidential instances
                else:
                    console.print(
                        "\n\nInitialize a confidential session using:\n\n",
                        Text.assemble(
                            "  aleph instance confidential-init-session ",
                            item_hash_text,
                            style="italic",
                        ),
                        "\n\nThen start it using:\n\n",
                        Text.assemble(
                            "  aleph instance confidential-start ",
                            item_hash_text,
                            style="italic",
                        ),
                        "\n\nOr just use the all-in-one command:\n\n",
                        Text.assemble(
                            "  aleph instance confidential ",
                            item_hash_text,
                            "\n",
                            style="italic",
                        ),
                    )
        # Instances started automatically by the scheduler (hold-tier non-confidential)
        else:
            console.print(
                f"Your instance {item_hash_text} is registered to be deployed on aleph.im.",
                "\nThe scheduler usually takes a few minutes to set it up and start it.",
            )
            if verbose:
                console.print(
                    "\n\nTo get the IPv6 address of the instance, check out:\n\n",
                    Text.assemble(
                        "  aleph instance list\n",
                        style="italic",
                    ),
                )
        return item_hash, crn_url


@app.command()
async def delete(
    item_hash: str = typer.Argument(..., help="Instance item hash to forget"),
    reason: str = typer.Option("User deletion", help="Reason for deleting the instance"),
    crn_url: Optional[str] = typer.Option(None, help=help_strings.CRN_URL_VM_DELETION),
    private_key: Optional[str] = settings.PRIVATE_KEY_STRING,
    private_key_file: Optional[Path] = settings.PRIVATE_KEY_FILE,
    print_message: bool = typer.Option(False),
    debug: bool = False,
):
    """Delete an instance, unallocating all resources associated with it. Associated VM will be stopped and erased. Immutable volumes will not be deleted."""

    setup_logging(debug)

    account = _load_account(private_key, private_key_file)
    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        try:
            existing_message: InstanceMessage = await client.get_message(
                item_hash=ItemHash(item_hash), message_type=InstanceMessage
            )

        except MessageNotFoundError:
            echo("Instance does not exist")
            raise typer.Exit(code=1)
        except ForgottenMessageError:
            echo("Instance already forgotten")
            raise typer.Exit(code=1)
        if existing_message.sender != account.get_address():
            echo("You are not the owner of this instance")
            raise typer.Exit(code=1)

        # If PAYG, retrieve flow price
        payment: Optional[Payment] = existing_message.content.payment
        price: Optional[PriceResponse] = None
        if safe_getattr(payment, "type") == PaymentType.superfluid:
            price = await client.get_program_price(item_hash)

        # Check status of the instance and eventually erase associated VM
        node_list: NodeInfo = await _fetch_nodes()
        _, info = await fetch_vm_info(existing_message, node_list)
        auto_scheduled = info["allocation_type"] == help_strings.ALLOCATION_AUTO
        crn_url = str(info["crn_url"])
        if not auto_scheduled and crn_url:
            try:
                status = await erase(item_hash, crn_url, private_key, private_key_file, True, debug)
                if status == 1:
                    echo(f"No associated VM on {crn_url}. Skipping...")
            except Exception:
                echo(f"Failed to erase associated VM on {crn_url}. Skipping...")
        else:
            echo(f"Instance {item_hash} was auto-scheduled, VM will be erased automatically.")

        # Check for streaming payment and eventually stop it
        if payment and payment.type == PaymentType.superfluid and payment.receiver and isinstance(account, ETHAccount):
            account.switch_chain(payment.chain)
            if account.superfluid_connector and price:
                flow_hash = await update_flow(
                    account, payment.receiver, Decimal(price.required_tokens), FlowUpdate.REDUCE
                )
                if flow_hash:
                    echo(f"Flow {flow_hash} has been deleted.")

        message, status = await client.forget(hashes=[ItemHash(item_hash)], reason=reason)
        if print_message:
            echo(f"{message.json(indent=4)}")
        echo(f"Instance {item_hash} has been deleted.")


async def _show_instances(messages: List[InstanceMessage], node_list: NodeInfo):
    table = Table(box=box.SIMPLE_HEAVY)
    table.add_column(f"Instances [{len(messages)}]", style="blue", overflow="fold")
    table.add_column("Specifications", style="magenta")
    table.add_column("Logs", style="blue", overflow="fold")

    scheduler_responses = dict(await asyncio.gather(*[fetch_vm_info(message, node_list) for message in messages]))
    uninitialized_confidential_found = False
    for message in messages:
        info = scheduler_responses[message.item_hash]
        if info["ipv6_logs"] == help_strings.VM_NOT_READY:
            uninitialized_confidential_found = True
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
        link = f"https://explorer.aleph.im/address/ETH/{message.sender}/message/INSTANCE/{message.item_hash}"
        # link = f"{settings.API_HOST}/api/v0/messages/{message.item_hash}"
        item_hash_link = Text.from_markup(f"[link={link}]{message.item_hash}[/link]", style="bright_cyan")
        is_hold = str(info["payment"]).startswith("hold")
        payment = Text.assemble(
            "Payment: ",
            Text(
                str(info["payment"]).capitalize(),
                style="red" if is_hold else "orange3",
            ),
        )
        cost: Text | str = ""
        if not is_hold:
            async with AlephHttpClient(api_server=settings.API_HOST) as client:
                price: PriceResponse = await client.get_program_price(message.item_hash)
                psec = Text(f"{price.required_tokens:.7f}/sec", style="bright_magenta")
                phour = Text(f"{3600*price.required_tokens:.2f}/hour", style="bright_magenta")
                pday = Text(f"{86400*price.required_tokens:.2f}/day", style="bright_magenta")
                pmonth = Text(f"{2592000*price.required_tokens:.2f}/month", style="bright_magenta")
                cost = Text.assemble("Aleph cost: ", psec, " | ", phour, " | ", pday, " | ", pmonth, "\n")
        confidential = (
            Text.assemble("Type: ", Text("Confidential", style="green"))
            if info["confidential"]
            else Text.assemble("Type: ", Text("Regular", style="grey50"))
        )
        chain = Text.assemble("Chain: ", Text(str(info["chain"]), style="cyan"))
        instance = Text.assemble(
            "Item Hash ↓\t     Name: ",
            name,
            "\n",
            item_hash_link,
            "\n",
            payment,
            "  ",
            confidential,
            "\n",
            cost,
            chain,
        )
        specifications = (
            f"vCPUs: {message.content.resources.vcpus}\n"
            f"RAM: {message.content.resources.memory / 1_024:.2f} GiB\n"
            f"Disk: {message.content.rootfs.size_mib / 1_024:.2f} GiB\n"
            f"HyperV: {safe_getattr(message, 'content.environment.hypervisor.value').capitalize() if safe_getattr(message, 'content.environment.hypervisor') else 'Firecracker'}\n"
        )
        status_column = Text.assemble(
            Text.assemble(
                Text("Allocation: ", style="blue"),
                Text(
                    str(info["allocation_type"]) + "\n",
                    style="magenta3" if info["allocation_type"] == help_strings.ALLOCATION_MANUAL else "deep_sky_blue1",
                ),
            ),
            Text.assemble(
                Text("Target CRN: ", style="blue"),
                Text(
                    str(info["crn_url"]) + "\n",
                    style="green1" if str(info["crn_url"]).startswith("http") else "dark_slate_gray1",
                ),
            ),
            Text.assemble(
                Text("IPv6: ", style="blue"),
                Text(str(info["ipv6_logs"])),
                style="bright_yellow" if len(str(info["ipv6_logs"]).split(":")) == 8 else "dark_orange",
            ),
        )
        table.add_row(instance, specifications, status_column)
        table.add_section()
    console = Console()
    console.print(
        f"\n[bold]Address:[/bold] {messages[0].content.address}",
    )
    console.print(table)
    if uninitialized_confidential_found:
        item_hash_field = Text("<vm-item-hash>", style="bright_cyan")
        crn_url_field = Text("<crn-url>", style="blue")
        console.print(
            "To start uninitialized confidential instance(s), use:\n\n",
            Text.assemble(
                "  aleph instance confidential-init-session ",
                item_hash_field,
                "\n",
                style="italic",
            ),
            Text.assemble(
                "  aleph instance confidential-start ",
                item_hash_field,
                style="italic",
            ),
            "\n\nOr just use the all-in-one command:\n\n",
            Text.assemble(
                "  aleph instance confidential ",
                item_hash_field,
                "\n",
                style="italic",
            ),
        )
    console.print(
        "To connect to an instance, use:\n\n",
        Text.assemble(
            "  ssh root@",
            Text("<ipv6-address>", style="yellow"),
            " -i ",
            Text("<ssh-pubkey-file>", style="orange3"),
            "\n",
            style="italic",
        ),
    )


@app.command()
async def list(
    address: Optional[str] = typer.Option(None, help="Owner address of the instance"),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    json: bool = typer.Option(default=False, help="Print as json instead of rich table"),
    debug: bool = False,
):
    """List all instances associated to an account"""

    setup_logging(debug)

    if address is None:
        account = _load_account(private_key, private_key_file)
        address = account.get_address()

    async with AlephHttpClient(api_server=settings.API_HOST) as client:
        resp = await client.get_messages(
            message_filter=MessageFilter(
                message_types=[MessageType.instance],
                addresses=[address],
            ),
            page_size=100,
        )
        messages = await filter_only_valid_messages(resp.messages)
        if not messages:
            echo(f"Address: {address}\n\nNo instance found\n")
            raise typer.Exit(code=1)
        if json:
            echo(messages.json(indent=4))
        else:
            # Since we filtered on message type, we can safely cast as InstanceMessage.
            messages = cast(List[InstanceMessage], messages)
            resource_nodes: NodeInfo = await _fetch_nodes()
            await _show_instances(messages, resource_nodes)


@app.command()
async def expire(
    vm_id: str = typer.Argument(..., help="VM item hash to expire"),
    domain: Optional[str] = typer.Option(None, help="CRN domain on which the VM is running"),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    """Expire an instance"""

    setup_logging(debug)

    domain = (
        (domain and sanitize_url(domain))
        or await find_crn_of_vm(vm_id)
        or Prompt.ask("URL of the CRN (Compute node) on which the VM is running")
    )

    account = _load_account(private_key, private_key_file)

    async with VmClient(account, domain) as manager:
        status, result = await manager.expire_instance(vm_id=vm_id)
        if status != 200:
            echo(f"Status: {status}")
            return 1
        echo(f"VM expired on CRN: {domain}")


@app.command()
async def erase(
    vm_id: str = typer.Argument(..., help="VM item hash to erase"),
    domain: Optional[str] = typer.Option(None, help="CRN domain on which the VM is stored or running"),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    silent: bool = False,
    debug: bool = False,
):
    """Erase an instance stored or running on a CRN"""

    setup_logging(debug)

    domain = (
        (domain and sanitize_url(domain))
        or await find_crn_of_vm(vm_id)
        or Prompt.ask("URL of the CRN (Compute node) on which the VM is stored or running")
    )

    account = _load_account(private_key, private_key_file)

    async with VmClient(account, domain) as manager:
        status, result = await manager.erase_instance(vm_id=vm_id)
        if status != 200:
            if not silent:
                echo(f"Status: {status}")
            return 1
        echo(f"VM erased on CRN: {domain}")


@app.command()
async def reboot(
    vm_id: str = typer.Argument(..., help="VM item hash to reboot"),
    domain: Optional[str] = typer.Option(None, help="CRN domain on which the VM is running"),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    """Reboot an instance"""

    setup_logging(debug)

    domain = (
        (domain and sanitize_url(domain))
        or await find_crn_of_vm(vm_id)
        or Prompt.ask("URL of the CRN (Compute node) on which the VM is running")
    )

    account = _load_account(private_key, private_key_file)

    async with VmClient(account, domain) as manager:
        status, result = await manager.reboot_instance(vm_id=vm_id)
        if status != 200:
            echo(f"Status: {status}")
            return 1
        echo(f"VM rebooted on CRN: {domain}")


@app.command()
async def allocate(
    vm_id: str = typer.Argument(..., help="VM item hash to allocate"),
    domain: Optional[str] = typer.Option(None, help="CRN domain on which the VM will be allocated"),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    """Notify a CRN to start an instance (for Pay-As-You-Go and confidential instances only)"""

    setup_logging(debug)

    domain = (
        (domain and sanitize_url(domain))
        or await find_crn_of_vm(vm_id)
        or Prompt.ask("URL of the CRN (Compute node) on which the VM will be allocated")
    )

    account = _load_account(private_key, private_key_file)

    async with VmClient(account, domain) as manager:
        status, result = await manager.start_instance(vm_id=vm_id)
        if status != 200:
            echo(f"Status: {status}")
            return 1
        echo(f"VM allocated on CRN: {domain}")


@app.command()
async def logs(
    vm_id: str = typer.Argument(..., help="VM item hash to retrieve the logs from"),
    domain: Optional[str] = typer.Option(None, help="CRN domain on which the VM is running"),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    """Retrieve the logs of an instance"""
    setup_logging(debug)

    domain = (
        (domain and sanitize_url(domain))
        or await find_crn_of_vm(vm_id)
        or Prompt.ask("URL of the CRN (Compute node) on which the instance is running")
    )

    account = _load_account(private_key, private_key_file)

    async with VmClient(account, domain) as manager:
        try:
            async for log in manager.get_logs(vm_id=vm_id):
                log_data = json.loads(log)
                if "message" in log_data:
                    echo(log_data["message"])
        except aiohttp.ClientConnectorError as e:
            echo(f"Unable to connect to domain: {domain}\nError: {e}")
        except aiohttp.ClientResponseError:
            echo(f"No VM associated with {vm_id} are currently running on {domain}")


@app.command()
async def stop(
    vm_id: str = typer.Argument(..., help="VM item hash to stop"),
    domain: Optional[str] = typer.Option(None, help="CRN domain on which the VM is running"),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    """Stop an instance"""

    setup_logging(debug)

    domain = (
        (domain and sanitize_url(domain))
        or await find_crn_of_vm(vm_id)
        or Prompt.ask("URL of the CRN (Compute node) on which the instance is running")
    )

    account = _load_account(private_key, private_key_file)

    async with VmClient(account, domain) as manager:
        status, result = await manager.stop_instance(vm_id=vm_id)
        if status != 200:
            echo(f"Status : {status}")
            return 1
        echo(f"VM stopped on CRN: {domain}")


@app.command()
async def confidential_init_session(
    vm_id: str = typer.Argument(..., help="VM item hash to initialize the session for"),
    domain: Optional[str] = typer.Option(None, help="CRN domain on which the session will be initialized"),
    policy: int = typer.Option(default=0x1),
    keep_session: bool = typer.Option(None, help=help_strings.KEEP_SESSION),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    "Initialize a confidential communication session with the VM"
    assert settings.CONFIG_HOME

    session_dir = Path(settings.CONFIG_HOME) / "confidential_sessions" / vm_id
    session_dir.mkdir(exist_ok=True, parents=True)

    setup_logging(debug)

    domain = (
        (domain and sanitize_url(domain))
        or await find_crn_of_vm(vm_id)
        or Prompt.ask("URL of the CRN (Compute node) on which the session will be initialized")
    )

    account = _load_account(private_key, private_key_file)

    sevctl_path = find_sevctl_or_exit()

    client = VmConfidentialClient(account, sevctl_path, domain)
    godh_path = session_dir / "vm_godh.b64"

    if godh_path.exists() and keep_session is None:
        keep_session = not Confirm.ask(
            "Session already initiated for this instance, are you sure you want to override the previous one? You won't be able to communicate with already running VM"
        )
        if keep_session:
            echo("Keeping already initiated session")

    # Generate sessions certificate files
    if not ((session_dir / "vm_godh.b64").exists() and keep_session):

        code, platform_file = await client.get_certificates()
        if code != 200:
            echo(
                "Failed to retrieve platform certificate from the CRN. This node might be temporary down, please try again later. If the problem persist, contact the node operator."
            )
            return 1

        # pathlib.Path.rename raises "Invalid cross-device link" if the destination is not on the current filesystem.
        platform_certificate_path = shutil.move(platform_file, session_dir / "platform_certificate.pem")
        certificate_prefix = str(session_dir) + "/vm"

        # Create local session files
        await client.create_session(certificate_prefix, platform_certificate_path, policy)

        logger.info(f"Certificate created in {platform_certificate_path}")

    vm_hash = ItemHash(vm_id)
    godh_path = session_dir / "vm_godh.b64"
    session_path = session_dir / "vm_session.b64"
    assert godh_path.exists()
    await client.initialize(vm_hash, session_path, godh_path)
    echo("Confidential Session with VM and CRN initiated")
    await client.close()


def find_sevctl_or_exit() -> Path:
    "Find sevctl in path, exit with message if not available"
    sevctl_path = shutil.which("sevctl")
    if sevctl_path is None:
        echo("sevctl binary is not available. Please install sevctl, ensure it is in the PATH and try again.")
        echo("Instructions for setup https://docs.aleph.im/computing/confidential/requirements/")
        raise typer.Exit(code=1)
    return Path(sevctl_path)


@app.command()
async def confidential_start(
    vm_id: str = typer.Argument(..., help="VM item hash to start"),
    domain: Optional[str] = typer.Option(None, help="CRN domain on which the VM will be started"),
    firmware_hash: str = typer.Option(
        settings.DEFAULT_CONFIDENTIAL_FIRMWARE_HASH, help=help_strings.CONFIDENTIAL_FIRMWARE_HASH
    ),
    firmware_file: str = typer.Option(None, help=help_strings.PRIVATE_KEY),
    vm_secret: str = typer.Option(None, help=help_strings.VM_SECRET),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    "Validate the authenticity of the VM and start it"
    assert settings.CONFIG_HOME
    session_dir = Path(settings.CONFIG_HOME) / "confidential_sessions" / vm_id
    session_dir.mkdir(exist_ok=True, parents=True)

    setup_logging(debug)
    account = _load_account(private_key, private_key_file)
    sevctl_path = find_sevctl_or_exit()

    domain = (
        (domain and sanitize_url(domain))
        or await find_crn_of_vm(vm_id)
        or Prompt.ask("URL of the CRN (Compute node) on which the VM will be started")
    )

    client = VmConfidentialClient(account, sevctl_path, domain)

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
        return 1
    echo("Measurement are authentic")

    secret_key = vm_secret or Prompt.ask("Please enter secret to start the VM", password=True)

    encoded_packet_header, encoded_secret = await client.build_secret(tek_path, tik_path, sev_data, secret_key)
    await client.inject_secret(vm_hash, encoded_packet_header, encoded_secret)
    await client.close()
    console = Console()
    console.print(
        "Your instance is currently starting...\n\nLogs can be fetched using:\n\n",
        Text.assemble(
            "  aleph instance logs ",
            Text(vm_id, style="bright_cyan"),
            style="italic",
        ),
        "\n\nTo get the IPv6 address of the instance, check out:\n\n",
        Text.assemble(
            "  aleph instance list\n",
            style="italic",
        ),
    )


@app.command()
async def confidential(
    vm_id: Optional[str] = typer.Argument(default=None, help=help_strings.VM_ID),
    crn_url: Optional[str] = typer.Option(default=None, help=help_strings.CRN_URL),
    crn_hash: Optional[str] = typer.Option(default=None, help=help_strings.CRN_HASH),
    policy: int = typer.Option(default=0x1),
    confidential_firmware: str = typer.Option(
        default=settings.DEFAULT_CONFIDENTIAL_FIRMWARE, help=help_strings.CONFIDENTIAL_FIRMWARE
    ),
    firmware_hash: str = typer.Option(
        settings.DEFAULT_CONFIDENTIAL_FIRMWARE_HASH, help=help_strings.CONFIDENTIAL_FIRMWARE_HASH
    ),
    firmware_file: Optional[str] = typer.Option(None, help=help_strings.PRIVATE_KEY),
    keep_session: Optional[bool] = typer.Option(None, help=help_strings.KEEP_SESSION),
    vm_secret: Optional[str] = typer.Option(None, help=help_strings.VM_SECRET),
    payment_type: Optional[str] = typer.Option(
        None,
        help=help_strings.PAYMENT_TYPE,
        callback=lambda pt: None if pt is None else PaymentType.hold if pt == "nft" else PaymentType(pt),
        metavar=f"[{'|'.join(PaymentType)}|nft]",
    ),
    payment_chain: Optional[Chain] = typer.Option(
        None, help=help_strings.PAYMENT_CHAIN, metavar=f"[{'|'.join([Chain.ETH, Chain.AVAX, Chain.BASE])}]"
    ),
    name: Optional[str] = typer.Option(None, help=help_strings.INSTANCE_NAME),
    rootfs: Optional[str] = typer.Option(None, help=help_strings.ROOTFS),
    rootfs_size: Optional[int] = typer.Option(None, help=help_strings.ROOTFS_SIZE),
    vcpus: Optional[int] = typer.Option(None, help=help_strings.VCPUS),
    memory: Optional[int] = typer.Option(None, help=help_strings.MEMORY),
    timeout_seconds: float = typer.Option(
        settings.DEFAULT_VM_TIMEOUT,
        help=help_strings.TIMEOUT_SECONDS,
    ),
    ssh_pubkey_file: Path = typer.Option(
        Path("~/.ssh/id_rsa.pub").expanduser(),
        help=help_strings.SSH_PUBKEY_FILE,
    ),
    skip_volume: bool = typer.Option(False, help=help_strings.SKIP_VOLUME),
    persistent_volume: Optional[List[str]] = typer.Option(None, help=help_strings.PERSISTENT_VOLUME),
    ephemeral_volume: Optional[List[str]] = typer.Option(None, help=help_strings.EPHEMERAL_VOLUME),
    immutable_volume: Optional[List[str]] = typer.Option(
        None,
        help=help_strings.IMMUTABLE_VOLUME,
    ),
    channel: Optional[str] = typer.Option(default=settings.DEFAULT_CHANNEL, help=help_strings.CHANNEL),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    """Create, start and unlock a confidential VM (all-in-one command)

    This command combines the following commands:
    \n\t- create (unless vm_id is passed)
    \n\t- allocate
    \n\t- confidential-init-session
    \n\t- confidential-start
    """

    # Ensure sevctl is accessible before we start process with user
    find_sevctl_or_exit()
    allocated = False
    if not vm_id or len(vm_id) != 64:
        vm_id, crn_url = await create(
            payment_type=payment_type,
            payment_chain=payment_chain,
            hypervisor=HypervisorType.qemu,
            name=name,
            rootfs=rootfs,
            rootfs_size=rootfs_size,
            vcpus=vcpus,
            memory=memory,
            timeout_seconds=timeout_seconds,
            ssh_pubkey_file=ssh_pubkey_file,
            crn_hash=crn_hash,
            crn_url=crn_url,
            confidential=True,
            confidential_firmware=confidential_firmware,
            skip_volume=skip_volume,
            persistent_volume=persistent_volume,
            ephemeral_volume=ephemeral_volume,
            immutable_volume=immutable_volume,
            channel=channel,
            private_key=private_key,
            private_key_file=private_key_file,
            print_messages=False,
            verbose=False,
            debug=debug,
        )
        if not vm_id or len(vm_id) != 64:
            echo("Could not create the VM")
            return 1
        allocated = vm_id is not None

    crn_url = (
        (crn_url and sanitize_url(crn_url))
        or await find_crn_of_vm(vm_id)
        or Prompt.ask("URL of the CRN (Compute node) on which the instance is running")
    )

    if not allocated:
        allocated = (
            await allocate(
                vm_id=vm_id, domain=crn_url, private_key=private_key, private_key_file=private_key_file, debug=debug
            )
        ) is None
        if not allocated:
            echo("Could not allocate the VM")
            return 1

    initialized = (
        await confidential_init_session(
            vm_id=vm_id,
            domain=crn_url,
            policy=policy,
            keep_session=keep_session,
            private_key=private_key,
            private_key_file=private_key_file,
            debug=debug,
        )
    ) is None
    if not initialized:
        echo("Could not initialize the session")
        return 1

    await confidential_start(
        vm_id=vm_id,
        domain=crn_url,
        firmware_hash=firmware_hash,
        firmware_file=firmware_file,
        vm_secret=vm_secret,
        private_key=private_key,
        private_key_file=private_key_file,
        debug=debug,
    )
