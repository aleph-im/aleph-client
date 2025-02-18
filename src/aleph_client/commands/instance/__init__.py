from __future__ import annotations

import asyncio
import builtins
import json
import logging
import shutil
from decimal import Decimal
from pathlib import Path
from typing import Any, Optional, Union, cast

import aiohttp
import typer
from aleph.sdk import AlephHttpClient, AuthenticatedAlephHttpClient
from aleph.sdk.account import _load_account
from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.client.vm_client import VmClient
from aleph.sdk.client.vm_confidential_client import VmConfidentialClient
from aleph.sdk.conf import load_main_configuration, settings
from aleph.sdk.evm_utils import (
    FlowUpdate,
    get_chains_with_holding,
    get_chains_with_super_token,
)
from aleph.sdk.exceptions import (
    ForgottenMessageError,
    InsufficientFundsError,
    MessageNotFoundError,
)
from aleph.sdk.query.filters import MessageFilter
from aleph.sdk.query.responses import PriceResponse
from aleph.sdk.types import StorageEnum, TokenType
from aleph.sdk.utils import (
    calculate_firmware_hash,
    displayable_amount,
    make_instance_content,
    safe_getattr,
)
from aleph_message.models import Chain, InstanceMessage, MessageType, StoreMessage
from aleph_message.models.execution.base import Payment, PaymentType
from aleph_message.models.execution.environment import (
    GpuProperties,
    HostRequirements,
    HypervisorType,
    NodeRequirements,
    TrustedExecutionEnvironment,
)
from aleph_message.models.item_hash import ItemHash
from click import echo
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from aleph_client.commands import help_strings
from aleph_client.commands.account import get_balance
from aleph_client.commands.instance.display import CRNTable
from aleph_client.commands.instance.network import (
    fetch_crn_info,
    fetch_crn_list,
    fetch_settings,
    fetch_vm_info,
    find_crn_of_vm,
)
from aleph_client.commands.pricing import PricingEntity, SelectedTier, fetch_pricing
from aleph_client.commands.utils import (
    filter_only_valid_messages,
    find_sevctl_or_exit,
    found_gpus_by_model,
    get_or_prompt_volumes,
    setup_logging,
    str_to_datetime,
    validate_ssh_pubkey_file,
    validated_int_prompt,
    validated_prompt,
    wait_for_confirmed_flow,
    wait_for_processed_instance,
    yes_no_input,
)
from aleph_client.utils import AsyncTyper, sanitize_url

logger = logging.getLogger(__name__)
app = AsyncTyper(no_args_is_help=True)

metavar_valid_payment_types = f"[{'|'.join(PaymentType)}|nft]"
hold_chains = [*get_chains_with_holding(), Chain.SOL]
metavar_valid_chains = f"[{'|'.join(hold_chains)}]"
super_token_chains = get_chains_with_super_token()
metavar_valid_payg_chains = f"[{'|'.join(super_token_chains)}]"


@app.command()
async def create(
    payment_type: Optional[str] = typer.Option(
        None,
        help=help_strings.PAYMENT_TYPE,
        callback=lambda pt: None if pt is None else pt.lower(),
        metavar=metavar_valid_payment_types,
        case_sensitive=False,
    ),
    payment_chain: Optional[Chain] = typer.Option(
        None,
        help=help_strings.PAYMENT_CHAIN,
        metavar=metavar_valid_chains,
        case_sensitive=False,
    ),
    hypervisor: HypervisorType = typer.Option(HypervisorType.qemu, help=help_strings.HYPERVISOR),
    name: Optional[str] = typer.Option(None, help=help_strings.INSTANCE_NAME),
    rootfs: Optional[str] = typer.Option(None, help=help_strings.ROOTFS),
    compute_units: Optional[int] = typer.Option(None, help=help_strings.COMPUTE_UNITS),
    vcpus: Optional[int] = typer.Option(None, help=help_strings.VCPUS),
    memory: Optional[int] = typer.Option(None, help=help_strings.MEMORY),
    rootfs_size: Optional[int] = typer.Option(None, help=help_strings.ROOTFS_SIZE),
    timeout_seconds: float = typer.Option(
        settings.DEFAULT_VM_TIMEOUT,
        help=help_strings.TIMEOUT_SECONDS,
    ),
    ssh_pubkey_file: Path = typer.Option(
        Path("~/.ssh/id_rsa.pub").expanduser(),
        help=help_strings.SSH_PUBKEY_FILE,
    ),
    address: Optional[str] = typer.Option(None, help=help_strings.ADDRESS_PAYER),
    crn_hash: Optional[str] = typer.Option(None, help=help_strings.CRN_HASH),
    crn_url: Optional[str] = typer.Option(None, help=help_strings.CRN_URL),
    confidential: bool = typer.Option(False, help=help_strings.CONFIDENTIAL_OPTION),
    confidential_firmware: str = typer.Option(
        default=settings.DEFAULT_CONFIDENTIAL_FIRMWARE, help=help_strings.CONFIDENTIAL_FIRMWARE
    ),
    gpu: bool = typer.Option(False, help=help_strings.GPU_OPTION),
    premium: Optional[bool] = typer.Option(None, help=help_strings.GPU_PREMIUM_OPTION),
    skip_volume: bool = typer.Option(False, help=help_strings.SKIP_VOLUME),
    persistent_volume: Optional[list[str]] = typer.Option(None, help=help_strings.PERSISTENT_VOLUME),
    ephemeral_volume: Optional[list[str]] = typer.Option(None, help=help_strings.EPHEMERAL_VOLUME),
    immutable_volume: Optional[list[str]] = typer.Option(
        None,
        help=help_strings.IMMUTABLE_VOLUME,
    ),
    crn_auto_tac: bool = typer.Option(False, help=help_strings.CRN_AUTO_TAC),
    channel: Optional[str] = typer.Option(default=settings.DEFAULT_CHANNEL, help=help_strings.CHANNEL),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    print_message: bool = typer.Option(False),
    verbose: bool = typer.Option(True),
    debug: bool = False,
) -> tuple[ItemHash, Optional[str], Chain]:
    """Create and register a new instance on aleph.im"""
    setup_logging(debug)
    console = Console()

    # Loads ssh pubkey
    try:
        ssh_pubkey_file = validate_ssh_pubkey_file(ssh_pubkey_file)
    except ValueError:
        ssh_pubkey_file = Path(
            validated_prompt(
                f"{ssh_pubkey_file} does not exist.\nPlease enter the path to a ssh pubkey to access your instance",
                validate_ssh_pubkey_file,
            )
        )
    ssh_pubkey: str = ssh_pubkey_file.read_text(encoding="utf-8").strip()

    # Populates account / address
    account = _load_account(private_key, private_key_file, chain=payment_chain)
    address = address or settings.ADDRESS_TO_USE or account.get_address()

    # Loads default configuration if no chain is set
    if payment_chain is None:
        config = load_main_configuration(settings.CONFIG_FILE)
        if config is not None:
            payment_chain = config.chain
            console.print(f"Preset to default chain: [green]{payment_chain}[/green]")
        else:
            console.print("No active chain selected in configuration.")

    # Populates payment type if not set
    if not payment_type:
        payment_type = Prompt.ask(
            "Which payment type do you want to use?",
            choices=[ptype.value for ptype in PaymentType] + ["nft"],
            default=PaymentType.superfluid.value,
        )

    # Force-switches if NFT payment-type
    nft_chains = [Chain.AVAX, Chain.BASE, Chain.SOL]
    if payment_type == "nft":
        payment_type = PaymentType.hold
        if payment_chain is None or payment_chain not in nft_chains:
            if payment_chain:
                console.print(
                    f"[red]{safe_getattr(payment_chain, 'value') or payment_chain}[/red]"
                    " incompatible with NFT vouchers."
                )
            payment_chain = Chain(
                Prompt.ask(
                    "On which chain did you claim your NFT voucher?",
                    choices=[nft_chain.value for nft_chain in nft_chains],
                    default=Chain.AVAX.value,
                )
            )
    elif payment_type in [ptype.value for ptype in PaymentType]:
        payment_type = PaymentType(payment_type)
    else:
        msg = f"Invalid payment-type: {payment_type}"
        raise ValueError(msg)

    # Checks if payment-chain is compatible with PAYG
    is_stream = payment_type != PaymentType.hold
    if is_stream:
        if address != account.get_address():
            console.print("Payment delegation is incompatible with Pay-As-You-Go.")
            raise typer.Exit(code=1)
        if payment_chain is None or payment_chain not in super_token_chains:
            if payment_chain:
                console.print(
                    f"[red]{safe_getattr(payment_chain, 'value') or payment_chain}[/red] incompatible with "
                    "Pay-As-You-Go."
                )
            payment_chain = Chain(
                Prompt.ask(
                    "Which chain do you want to use for Pay-As-You-Go?",
                    choices=super_token_chains,
                    default=Chain.AVAX.value,
                )
            )

    # Fallback for Hold-tier if no config / no chain is set / chain not in hold_chains
    elif payment_chain is None or payment_chain not in hold_chains:
        if payment_chain:
            console.print(
                f"[red]{safe_getattr(payment_chain, 'value') or payment_chain}[/red] incompatible with Hold-tier."
            )
        payment_chain = Chain(
            Prompt.ask(
                "Which chain do you want to use for Hold-tier?",
                choices=hold_chains,
                default=Chain.ETH.value,
            )
        )

    # Ensure hypervisor is compatible
    if hypervisor != HypervisorType.qemu:
        console.print("QEMU is now the only supported hypervisor. Firecracker has been deprecated for instances.")
        raise typer.Exit(code=1)

    os_choices = {
        "ubuntu22": settings.UBUNTU_22_QEMU_ROOTFS_ID,
        "ubuntu24": settings.UBUNTU_24_QEMU_ROOTFS_ID,
        "debian12": settings.DEBIAN_12_QEMU_ROOTFS_ID,
    }

    # Rootfs selection
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
        rootfs_message: Optional[StoreMessage] = None
        try:
            rootfs_message = await client.get_message(item_hash=rootfs, message_type=StoreMessage)
        except MessageNotFoundError:
            echo(f"Given rootfs volume {rootfs} does not exist on aleph.im")
        except ForgottenMessageError:
            echo(f"Given rootfs volume {rootfs} has been deleted on aleph.im")
        if not rootfs_message:
            raise typer.Exit(code=1)

    # Validate confidential firmware message exist
    confidential_firmware_as_hash = None
    if confidential:
        async with AlephHttpClient(api_server=settings.API_HOST) as client:
            confidential_firmware_as_hash = ItemHash(confidential_firmware)
            firmware_message: Optional[StoreMessage] = None
            try:
                firmware_message = await client.get_message(item_hash=confidential_firmware, message_type=StoreMessage)
            except MessageNotFoundError:
                echo("Confidential Firmware hash does not exist on aleph.im")
            except ForgottenMessageError:
                echo("Confidential Firmware hash has been deleted on aleph.im")
            if not firmware_message:
                raise typer.Exit(code=1)

    # Filter and prepare the list of available GPUs
    crn_list = None
    found_gpu_models: Optional[dict[str, dict[str, dict[str, int]]]] = None
    if gpu:
        echo("Fetching available GPU list...")
        crn_list = await fetch_crn_list(latest_crn_version=True, ipv6=True, stream_address=True, gpu=True)
        found_gpu_models = found_gpus_by_model(crn_list)
        premium = yes_no_input(f"{help_strings.GPU_PREMIUM_OPTION}?", default=False) if premium is None else premium

    pricing = await fetch_pricing()
    pricing_entity = (
        PricingEntity.INSTANCE_CONFIDENTIAL
        if confidential
        else (
            PricingEntity.INSTANCE_GPU_PREMIUM
            if gpu and premium
            else PricingEntity.INSTANCE_GPU_STANDARD if gpu else PricingEntity.INSTANCE
        )
    )
    tier = cast(  # Safe cast
        SelectedTier,
        pricing.display_table_for(
            pricing_entity,
            compute_units=compute_units or 0,
            vcpus=vcpus or 0,
            memory=memory or 0,
            disk=rootfs_size or 0,
            gpu_models=found_gpu_models,
            selector=True,
        ),
    )
    name = name or validated_prompt("Instance name", lambda x: x and len(x) < 65)
    vcpus = tier.vcpus
    memory = tier.memory
    rootfs_size = tier.disk
    gpu_model = tier.gpu_model
    volumes = []
    if not skip_volume:
        volumes = get_or_prompt_volumes(
            persistent_volume=persistent_volume,
            ephemeral_volume=ephemeral_volume,
            immutable_volume=immutable_volume,
        )

    # Early check with minimal cost (Gas + Aleph ERC20)
    available_funds = Decimal(0 if is_stream else (await get_balance(address))["available_amount"])
    try:
        if is_stream and isinstance(account, ETHAccount):
            if account.CHAIN != payment_chain:
                account.switch_chain(payment_chain)
            if safe_getattr(account, "superfluid_connector"):
                account.can_start_flow(tier.price.payg)
            else:
                echo("Superfluid connector not available on this chain.")
                raise typer.Exit(code=1)
        elif available_funds < tier.price.hold:
            raise InsufficientFundsError(TokenType.ALEPH, float(tier.price.hold), float(available_funds))
    except InsufficientFundsError as e:
        echo(e)
        raise typer.Exit(code=1) from e

    stream_reward_address = None
    crn = None
    if is_stream or confidential or gpu:
        if crn_url:
            try:
                crn_url = sanitize_url(crn_url)
            except aiohttp.InvalidURL as e:
                echo(f"Invalid URL provided: {crn_url}")
                raise typer.Exit(1) from e

        echo("Fetching compute resource node's list...")
        crn_list = await fetch_crn_list()  # Precache CRN list

        if (crn_url or crn_hash) and not gpu:
            try:
                crn = await fetch_crn_info(crn_url, crn_hash)
                if crn:
                    if (crn_hash and crn_hash != crn.hash) or (crn_url and crn_url != crn.url):
                        echo(
                            f"* Provided CRN *\nUrl: {crn_url}\nHash: {crn_hash}\n\n* Found CRN *\nUrl: "
                            f"{crn.url}\nHash: {crn.hash}\n\nMismatch between provided CRN and found CRN"
                        )
                        raise typer.Exit(1)
                    crn.display_crn_specs()
                else:
                    echo(f"* Provided CRN *\nUrl: {crn_url}\nHash: {crn_hash}\n\nProvided CRN not found")
                    raise typer.Exit(1)
            except Exception as e:
                raise typer.Exit(1) from e

        while not crn:
            crn_table = CRNTable(
                only_latest_crn_version=True,
                only_reward_address=is_stream,
                only_qemu=True,
                only_confidentials=confidential,
                only_gpu=gpu,
                only_gpu_model=gpu_model,
            )
            crn = await crn_table.run_async()
            if not crn:
                # User has ctrl-c
                raise typer.Exit(1)
            crn.display_crn_specs()
            if not yes_no_input("Deploy on this node?", default=True):
                crn = None
                continue
    elif crn_url or crn_hash:
        logger.debug(
            "`--crn-url` and/or `--crn-hash` arguments have been ignored.\nHold-tier regular "
            "instances are scheduled automatically on available CRNs by the Aleph.im network."
        )

    requirements, trusted_execution, gpu_requirement, tac_accepted = None, None, None, None
    if crn:
        stream_reward_address = safe_getattr(crn, "stream_reward_address") or ""
        if is_stream and not stream_reward_address:
            echo("Selected CRN does not have a defined or valid receiver address.")
            raise typer.Exit(1)
        if not safe_getattr(crn, "qemu_support"):
            echo("Selected CRN does not support QEMU hypervisor.")
            raise typer.Exit(1)
        if confidential:
            if not safe_getattr(crn, "confidential_computing"):
                echo("Selected CRN does not support confidential computing.")
                raise typer.Exit(1)
            trusted_execution = TrustedExecutionEnvironment(firmware=confidential_firmware_as_hash)
        if gpu:
            if not safe_getattr(crn, "gpu_support"):
                echo("Selected CRN does not support GPU computing.")
                raise typer.Exit(1)
            if crn.machine_usage and crn.machine_usage.gpu:
                if len(crn.machine_usage.gpu.available_devices) < 1:
                    echo("Selected CRN does not have any GPUs available.")
                    raise typer.Exit(1)

                table = Table(box=box.ROUNDED)
                table.add_column("Id", style="white", overflow="fold")
                table.add_column("Vendor", style="blue")
                table.add_column("Model GPU", style="magenta")
                available_gpus = crn.machine_usage.gpu.available_devices
                for index, available_gpu in enumerate(available_gpus):
                    table.add_row(str(index + 1), available_gpu.vendor, available_gpu.device_name)
                table.add_section()
                console.print(table)

                selected_gpu_number = (
                    validated_int_prompt("GPU Id to use", min_value=1, max_value=len(available_gpus)) - 1
                )
                selected_gpu = available_gpus[selected_gpu_number]
                gpu_selection = Text.from_markup(
                    f"[orange3]Vendor[/orange3]: {selected_gpu.vendor}\n[orange3]Model[/orange3]: "
                    f"{selected_gpu.device_name}"
                )
                console.print(
                    Panel(
                        gpu_selection,
                        title="Selected GPU",
                        border_style="bright_cyan",
                        expand=False,
                        title_align="left",
                    )
                )
                gpu_requirement = [
                    GpuProperties(
                        vendor=selected_gpu.vendor,
                        device_name=selected_gpu.device_name,
                        device_class=selected_gpu.device_class,
                        device_id=selected_gpu.device_id,
                    )
                ]
        if crn.terms_and_conditions:
            tac_accepted = await crn.display_terms_and_conditions(auto_accept=crn_auto_tac)
            if tac_accepted is None:
                echo("Failed to fetch terms and conditions.\nContact support or use a different CRN.")
                raise typer.Exit(1)
            elif not tac_accepted:
                echo("Terms & Conditions rejected: instance creation aborted.")
                raise typer.Exit(1)
            echo("Terms & Conditions accepted.")

        requirements = HostRequirements(
            node=NodeRequirements(
                node_hash=crn.hash,
                terms_and_conditions=(ItemHash(crn.terms_and_conditions) if tac_accepted else None),
            ),
            gpu=gpu_requirement,
        )

    payment = Payment(
        chain=payment_chain,
        receiver=stream_reward_address if stream_reward_address else None,
        type=payment_type,
    )

    content_dict: dict[str, Any] = {
        "address": address,
        "rootfs": rootfs,
        "rootfs_size": rootfs_size,
        "metadata": {"name": name},
        "memory": memory,
        "vcpus": vcpus,
        "timeout_seconds": timeout_seconds,
        "volumes": volumes,
        "ssh_keys": [ssh_pubkey],
        "hypervisor": hypervisor,
        "payment": payment,
        "requirements": requirements,
        "trusted_execution": trusted_execution,
    }

    # Estimate cost and check required balances (Gas + Aleph ERC20)
    required_tokens: Decimal
    async with AlephHttpClient(api_server=settings.API_HOST) as client:
        try:
            content = make_instance_content(**content_dict)
            price: PriceResponse = await client.get_estimated_price(content)
            required_tokens = Decimal(price.required_tokens)
        except Exception as e:
            echo(f"Failed to estimate instance cost, error: {e}")
            raise typer.Exit(code=1) from e

        try:
            if is_stream and isinstance(account, ETHAccount):
                account.can_start_flow(required_tokens)
            elif available_funds < required_tokens:
                raise InsufficientFundsError(TokenType.ALEPH, float(required_tokens), float(available_funds))
        except InsufficientFundsError as e:
            echo(e)
            raise typer.Exit(code=1) from e

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        try:
            message, status = await client.create_instance(
                **content_dict,
                channel=channel,
                storage_engine=StorageEnum.storage,
                sync=True,
            )
        except InsufficientFundsError as e:
            echo(
                f"Instance creation failed due to insufficient funds.\n"
                f"{address} on {account.CHAIN} has {e.available_funds} ALEPH but needs {e.required_funds} ALEPH."
            )
            raise typer.Exit(code=1) from e
        except Exception as e:
            echo(f"Instance creation failed:\n{e}")
            raise typer.Exit(code=1) from e
        if print_message:
            echo(f"{message.json(indent=4)}")

        item_hash: ItemHash = message.item_hash
        infos = []

        # Instances that need to be started by notifying a specific CRN
        crn_url = crn.url if crn and crn.url else None
        if crn and (is_stream or confidential or gpu):
            if not crn_url:
                # Not the ideal solution
                logger.debug(f"Cannot allocate {item_hash}: no CRN url")
                return item_hash, crn_url, payment_chain

            # Wait for the instance message to be processed
            async with aiohttp.ClientSession() as session:
                await wait_for_processed_instance(session, item_hash)

            # Pay-As-You-Go
            if is_stream and isinstance(account, ETHAccount):
                # Start the flows
                echo("Starting the flows...")
                fetched_settings = await fetch_settings()
                community_wallet_address = fetched_settings.get("community_wallet_address")
                flow_crn_amount = required_tokens * Decimal("0.8")
                flow_hash_crn = await account.manage_flow(
                    receiver=crn.stream_reward_address,
                    flow=flow_crn_amount,
                    update_type=FlowUpdate.INCREASE,
                )
                if flow_hash_crn:
                    await asyncio.sleep(5)  # 2nd flow tx fails if no delay
                    flow_hash_community = await account.manage_flow(
                        receiver=community_wallet_address,
                        flow=required_tokens - flow_crn_amount,
                        update_type=FlowUpdate.INCREASE,
                    )
                else:
                    echo("Flow creation failed. Check your wallet balance and try recreate the VM.")
                    raise typer.Exit(code=1)
                # Wait for the flow transactions to be confirmed
                await wait_for_confirmed_flow(account, crn.stream_reward_address)
                await wait_for_confirmed_flow(account, community_wallet_address)
                if flow_hash_crn and flow_hash_community:
                    flow_info = "\n".join(
                        f"[orange3]{key}[/orange3]: {value}"
                        for key, value in {
                            "$ALEPH": f"[violet]{displayable_amount(required_tokens, decimals=8)}/sec"
                            f" | {displayable_amount(3600*required_tokens, decimals=3)}/hour"
                            f" | {displayable_amount(86400*required_tokens, decimals=3)}/day"
                            f" | {displayable_amount(2628000*required_tokens, decimals=3)}/month[/violet]",
                            "Flow Distribution": "\n[bright_cyan]80% -> CRN wallet[/bright_cyan]"
                            f"\n  Address: {crn.stream_reward_address}\n  Tx: {flow_hash_crn}"
                            f"\n[bright_cyan]20% -> Community wallet[/bright_cyan]"
                            f"\n  Address: {community_wallet_address}\n  Tx: {flow_hash_community}",
                        }.items()
                    )
                    console.print(
                        Panel(
                            Text.from_markup(flow_info),
                            title="Flows Created",
                            border_style="violet",
                            expand=False,
                            title_align="left",
                        )
                    )

            # Notify CRN
            async with VmClient(account, crn.url) as crn_client:
                status, result = await crn_client.start_instance(vm_id=item_hash)
                logger.debug(status, result)
                if int(status) != 200:
                    echo(f"Could not allocate instance {item_hash} on CRN.")
                    return item_hash, crn_url, payment_chain

            infos += [
                Text.from_markup(f"Your instance [bright_cyan]{item_hash}[/bright_cyan] has been deployed on aleph.im.")
            ]
            if verbose:
                # PAYG-tier non-confidential instances
                if not confidential:
                    infos += [
                        Text.assemble(
                            "\n\nTo get your instance's IPv6, check out:\n",
                            Text.assemble(
                                "↳ aleph instance list",
                                style="italic",
                            ),
                            "\n\nTo access your instance's logs, use:\n",
                            Text.from_markup(
                                f"↳ aleph instance logs [bright_cyan]{item_hash}[/bright_cyan]",
                                style="italic",
                            ),
                        )
                    ]
                # All confidential instances
                else:
                    infos += [
                        Text.assemble(
                            "\n\nInitialize/start your confidential instance with:\n",
                            Text.from_markup(
                                f"↳ aleph instance confidential [bright_cyan]{item_hash}[/bright_cyan]",
                                style="italic",
                            ),
                        )
                    ]
        # Instances started automatically by the scheduler (hold-tier non-confidential)
        else:
            infos += [
                Text.from_markup(
                    f"Your instance [bright_cyan]{item_hash}[/bright_cyan] is registered to be deployed on aleph.im.\n"
                    "The scheduler usually takes a few minutes to set it up and start it."
                )
            ]
            if verbose:
                infos += [
                    Text.assemble(
                        "\n\nTo get your instance's IPv6, check out:\n",
                        Text.assemble(
                            "↳ aleph instance list",
                            style="italic",
                        ),
                        "\n\nTo access your instance's logs, use:\n",
                        Text.from_markup(
                            f"↳ aleph instance logs [bright_cyan]{item_hash}[/bright_cyan]",
                            style="italic",
                        ),
                    )
                ]
        console.print(
            Panel(
                Text.assemble(*infos), title="Instance Created", border_style="green", expand=False, title_align="left"
            )
        )
        return item_hash, crn_url, payment_chain


@app.command()
async def delete(
    item_hash: str = typer.Argument(..., help="Instance item hash to forget"),
    reason: str = typer.Option("User deletion", help="Reason for deleting the instance"),
    chain: Optional[Chain] = typer.Option(None, help=help_strings.PAYMENT_CHAIN_USED, metavar=metavar_valid_chains),
    domain: Optional[str] = typer.Option(None, help=help_strings.CRN_URL_VM_DELETION),
    private_key: Optional[str] = settings.PRIVATE_KEY_STRING,
    private_key_file: Optional[Path] = settings.PRIVATE_KEY_FILE,
    print_message: bool = typer.Option(False),
    debug: bool = False,
):
    """
    Delete an instance, unallocating all resources associated with it. Associated VM will be stopped and erased.
    Immutable volumes will not be deleted.
    """

    setup_logging(debug)

    account = _load_account(private_key, private_key_file, chain=chain)
    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        try:
            existing_message: InstanceMessage = await client.get_message(
                item_hash=ItemHash(item_hash), message_type=InstanceMessage
            )

        except MessageNotFoundError:
            echo("Instance does not exist")
            raise typer.Exit(code=1) from None
        except ForgottenMessageError:
            echo("Instance already deleted")
            raise typer.Exit(code=1) from None
        if existing_message.sender != account.get_address():
            echo("You are not the owner of this instance")
            raise typer.Exit(code=1)

        # If PAYG, retrieve creation time & flow price
        creation_time: float = existing_message.content.time
        payment: Optional[Payment] = existing_message.content.payment
        price: Optional[PriceResponse] = None
        if safe_getattr(payment, "type") == PaymentType.superfluid:
            price = await client.get_program_price(item_hash)

        # Ensure correct chain
        chain = existing_message.content.payment.chain  # type: ignore

        # Check status of the instance and eventually erase associated VM
        _, info = await fetch_vm_info(existing_message)
        auto_scheduled = info["allocation_type"] == help_strings.ALLOCATION_AUTO
        crn_url = (info["crn_url"] not in [help_strings.CRN_PENDING, help_strings.CRN_UNKNOWN] and info["crn_url"]) or (
            domain and sanitize_url(domain)
        )
        if not auto_scheduled:
            if not crn_url:
                echo("CRN domain not found or invalid. Skipping...")
            else:
                try:
                    async with VmClient(account, crn_url) as manager:
                        status, _ = await manager.erase_instance(vm_id=item_hash)
                        if status == 200:
                            echo(f"VM erased on CRN: {crn_url}")
                        else:
                            echo(f"No associated VM on {crn_url}. Skipping...")
                except Exception as e:
                    logger.debug(f"Error while deleting associated VM on {crn_url}: {e!s}")
                    echo(f"Failed to erase associated VM on {crn_url}. Skipping...")
        else:
            echo(f"Instance {item_hash} was auto-scheduled, VM will be erased automatically.")

        # Check for streaming payment and eventually stop it
        if payment and payment.type == PaymentType.superfluid and payment.receiver and isinstance(account, ETHAccount):
            if account.CHAIN != payment.chain:
                account.switch_chain(payment.chain)
            if safe_getattr(account, "superfluid_connector") and price:
                fetched_settings = await fetch_settings()
                community_wallet_timestamp = fetched_settings.get("community_wallet_timestamp")
                community_wallet_address = fetched_settings.get("community_wallet_address")
                try:  # Safety check to ensure account can transact
                    account.can_transact()
                except Exception as e:
                    echo(e)
                    raise typer.Exit(code=1) from e
                echo("Deleting the flows...")
                flow_crn_percent = Decimal("0.8") if community_wallet_timestamp < creation_time else Decimal("1")
                flow_com_percent = Decimal("1") - flow_crn_percent
                flow_hash_crn = await account.manage_flow(
                    payment.receiver, Decimal(price.required_tokens) * flow_crn_percent, FlowUpdate.REDUCE
                )
                if flow_hash_crn:
                    echo(f"CRN flow has been deleted successfully (Tx: {flow_hash_crn})")
                    if flow_com_percent > Decimal("0"):
                        await asyncio.sleep(5)
                        flow_hash_community = await account.manage_flow(
                            community_wallet_address,
                            Decimal(price.required_tokens) * flow_com_percent,
                            FlowUpdate.REDUCE,
                        )
                        if flow_hash_community:
                            echo(f"Community flow has been deleted successfully (Tx: {flow_hash_community})")
                    else:
                        echo("No community flow to delete (legacy instance). Skipping...")
                else:
                    echo("No flow to delete. Skipping...")

        message, status = await client.forget(hashes=[ItemHash(item_hash)], reason=reason)
        if print_message:
            echo(f"{message.json(indent=4)}")
        echo(f"Instance {item_hash} has been deleted.")


async def _show_instances(messages: builtins.list[InstanceMessage]):
    table = Table(box=box.ROUNDED, style="blue_violet")
    table.add_column(f"Instances [{len(messages)}]", style="blue", overflow="fold")
    table.add_column("Specifications", style="blue")
    table.add_column("Logs", style="blue", overflow="fold")

    await fetch_crn_list()  # Precache CRN list
    scheduler_responses = dict(await asyncio.gather(*[fetch_vm_info(message) for message in messages]))
    uninitialized_confidential_found = False
    for message in messages:
        info = scheduler_responses[message.item_hash]
        if info["confidential"] and info["ipv6_logs"] == help_strings.VM_NOT_READY:
            uninitialized_confidential_found = True
        name = Text(
            (
                message.content.metadata["name"]
                if hasattr(message.content, "metadata")
                and isinstance(message.content.metadata, dict)
                and "name" in message.content.metadata
                else "-"
            ),
            style="magenta3",
        )
        link = f"https://explorer.aleph.im/address/ETH/{message.sender}/message/INSTANCE/{message.item_hash}"
        # link = f"{settings.API_HOST}/api/v0/messages/{message.item_hash}"
        item_hash_link = Text.from_markup(f"[link={link}]{message.item_hash}[/link]", style="bright_cyan")
        payment = Text.assemble(
            "Payment: ",
            Text(
                info["payment"].capitalize().ljust(12),
                style="red" if info["payment"] == PaymentType.hold.value else "orange3",
            ),
        )
        confidential = Text.assemble(
            "Type: ", Text("Confidential", style="green") if info["confidential"] else Text("Regular", style="grey50")
        )
        chain = Text.assemble("Chain: ", Text(info["chain"].ljust(14), style="white"))
        created_at = Text.assemble(
            "Created at: ", Text(str(str_to_datetime(info["created_at"])).split(".", maxsplit=1)[0], style="orchid")
        )
        async with AlephHttpClient(api_server=settings.API_HOST) as client:
            price: PriceResponse = await client.get_program_price(message.item_hash)
            required_tokens = Decimal(price.required_tokens)
            if price.payment_type == PaymentType.hold.value:
                aleph_price = Text(f"{displayable_amount(required_tokens, decimals=3)} (fixed)", style="violet")
            else:
                psec = f"{displayable_amount(required_tokens, decimals=8)}/sec"
                phour = f"{displayable_amount(3600*required_tokens, decimals=3)}/hour"
                pday = f"{displayable_amount(86400*required_tokens, decimals=3)}/day"
                pmonth = f"{displayable_amount(2628000*required_tokens, decimals=3)}/month"
                aleph_price = Text.assemble(psec, " | ", phour, " | ", pday, " | ", pmonth, style="violet")
        cost = Text.assemble("\n$ALEPH: ", aleph_price)
        payer: Union[str, Text] = ""
        if message.sender != message.content.address:
            payer = Text.assemble("\nPayer: ", Text(str(message.sender), style="orange1"))
        instance = Text.assemble(
            "Item Hash ↓\t     Name: ",
            name,
            "\n",
            item_hash_link,
            "\n",
            payment,
            confidential,
            "\n",
            chain,
            created_at,
            cost,
            payer,
        )
        hypervisor = safe_getattr(message, "content.environment.hypervisor")
        specs = [
            f"vCPU: [magenta3]{message.content.resources.vcpus}[/magenta3]\n",
            f"RAM: [magenta3]{message.content.resources.memory / 1_024:.2f} GiB[/magenta3]\n",
            f"Disk: [magenta3]{message.content.rootfs.size_mib / 1_024:.2f} GiB[/magenta3]\n",
            f"HyperV: [magenta3]{hypervisor.capitalize() if hypervisor else 'Firecracker'}[/magenta3]",
        ]
        gpus = safe_getattr(message, "content.requirements.gpu")
        if gpus:
            specs += [f"\n[bright_yellow]GPU [[green]{len(gpus)}[/green]]:\n"]
            for gpu in gpus:
                specs += [f"• [green]{gpu.vendor}, {gpu.device_name}[green]"]
            specs += ["[/bright_yellow]"]
        specifications = Text.from_markup("".join(specs))
        status_column = Text.assemble(
            Text.assemble(
                Text("Allocation: ", style="blue"),
                Text(
                    info["allocation_type"] + "\n",
                    style="magenta3" if info["allocation_type"] == help_strings.ALLOCATION_MANUAL else "deep_sky_blue1",
                ),
            ),
            (
                Text.assemble(
                    Text("CRN Hash: ", style="blue"),
                    Text(info["crn_hash"] + "\n", style=("bright_cyan")),
                )
                if info["crn_hash"]
                else ""
            ),
            Text.assemble(
                Text("CRN Url: ", style="blue"),
                Text(
                    info["crn_url"] + "\n",
                    style="green1" if info["crn_url"].startswith("http") else "grey50",
                ),
            ),
            Text.assemble(
                Text("IPv6: ", style="blue"),
                Text(info["ipv6_logs"]),
                style="bright_yellow" if len(info["ipv6_logs"].split(":")) == 8 else "dark_orange",
            ),
            (
                Text.assemble(
                    Text(f"\n[{'✅' if info['tac_accepted'] else '❌'}] Accepted Terms & Conditions: "),
                    Text(
                        f"{info['tac_url']}",
                        style="orange1",
                    ),
                )
                if info["tac_hash"]
                else ""
            ),
        )
        table.add_row(instance, specifications, status_column)
        table.add_section()

    console = Console()
    console.print(table)

    infos = [Text.from_markup(f"[bold]Address:[/bold] [bright_cyan]{messages[0].sender}[/bright_cyan]")]
    if uninitialized_confidential_found:
        infos += [
            Text.assemble(
                "\n\nBoot uninitialized/unstarted confidential instances with:\n",
                Text.from_markup(
                    "↳  aleph instance confidential [bright_cyan]<vm-item-hash>[/bright_cyan]", style="italic"
                ),
            )
        ]
    infos += [
        Text.assemble(
            "\n\nConnect to an instance with:\n",
            Text.from_markup(
                "↳  ssh root@[yellow]<ipv6-address>[/yellow] [-i [orange3]<ssh-private-key-file>[/orange3]]",
                style="italic",
            ),
        )
    ]
    console.print(
        Panel(Text.assemble(*infos), title="Infos", border_style="bright_cyan", expand=False, title_align="left")
    )


@app.command(name="list")
async def list_instances(
    address: Optional[str] = typer.Option(None, help="Owner address of the instances"),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    chain: Optional[Chain] = typer.Option(None, help=help_strings.ADDRESS_CHAIN, metavar=metavar_valid_chains),
    json: bool = typer.Option(default=False, help="Print as json instead of rich table"),
    debug: bool = False,
):
    """List all instances associated to an account"""

    setup_logging(debug)

    account = _load_account(private_key, private_key_file, chain=chain)
    address = address or settings.ADDRESS_TO_USE or account.get_address()

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
            for message in messages:
                echo(message.json(indent=4))
        else:
            # Since we filtered on message type, we can safely cast as InstanceMessage.
            messages = cast(builtins.list[InstanceMessage], messages)
            await _show_instances(messages)


@app.command()
async def reboot(
    vm_id: str = typer.Argument(..., help="VM item hash to reboot"),
    domain: Optional[str] = typer.Option(None, help="CRN domain on which the VM is running"),
    chain: Optional[Chain] = typer.Option(None, help=help_strings.PAYMENT_CHAIN_USED, metavar=metavar_valid_chains),
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

    account = _load_account(private_key, private_key_file, chain=chain)

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
    chain: Optional[Chain] = typer.Option(None, help=help_strings.PAYMENT_CHAIN_USED, metavar=metavar_valid_chains),
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

    account = _load_account(private_key, private_key_file, chain=chain)

    async with VmClient(account, domain) as manager:
        status, result = await manager.start_instance(vm_id=vm_id)
        if status != 200:
            echo(f"Status: {status}\n{result}")
            return 1
        echo(f"VM allocated on CRN: {domain}")


@app.command()
async def logs(
    vm_id: str = typer.Argument(..., help="VM item hash to retrieve the logs from"),
    domain: Optional[str] = typer.Option(None, help="CRN domain on which the VM is running"),
    chain: Optional[Chain] = typer.Option(None, help=help_strings.PAYMENT_CHAIN_USED, metavar=metavar_valid_chains),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    """Retrieve the logs of an instance"""
    setup_logging(debug)

    domain = (domain and sanitize_url(domain)) or await find_crn_of_vm(vm_id) or Prompt.ask(help_strings.PROMPT_CRN_URL)

    account = _load_account(private_key, private_key_file, chain=chain)

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
    chain: Optional[Chain] = typer.Option(None, help=help_strings.PAYMENT_CHAIN_USED),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    """Stop an instance"""

    setup_logging(debug)

    domain = (domain and sanitize_url(domain)) or await find_crn_of_vm(vm_id) or Prompt.ask(help_strings.PROMPT_CRN_URL)

    account = _load_account(private_key, private_key_file, chain=chain)

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
    chain: Optional[Chain] = typer.Option(None, help=help_strings.PAYMENT_CHAIN_USED, metavar=metavar_valid_chains),
    policy: int = typer.Option(default=0x1),
    keep_session: bool = typer.Option(None, help=help_strings.KEEP_SESSION),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    """Initialize a confidential communication session with the VM"""

    setup_logging(debug)

    assert settings.CONFIG_HOME
    session_dir = Path(settings.CONFIG_HOME) / "confidential_sessions" / vm_id
    session_dir.mkdir(exist_ok=True, parents=True)

    domain = (
        (domain and sanitize_url(domain))
        or await find_crn_of_vm(vm_id)
        or Prompt.ask("URL of the CRN (Compute node) on which the session will be initialized")
    )

    account = _load_account(private_key, private_key_file, chain=chain)

    sevctl_path = find_sevctl_or_exit()

    client = VmConfidentialClient(account, sevctl_path, domain)
    godh_path = session_dir / "vm_godh.b64"

    if godh_path.exists() and keep_session is None:
        keep_session = not yes_no_input(
            "Session already initiated for this instance, are you sure you want to override the previous one? You "
            "won't be able to communicate with already running VM",
            default=True,
        )
        if keep_session:
            echo("Keeping already initiated session")

    # Generate sessions certificate files
    if not ((session_dir / "vm_godh.b64").exists() and keep_session):

        code, platform_file = await client.get_certificates()
        if code != 200:
            echo(
                "Failed to retrieve platform certificate from the CRN. This node might be temporary down, please try "
                "again later. If the problem persist, contact the node operator."
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
    try:
        await client.initialize(vm_hash, session_path, godh_path)
        echo("Confidential Session with VM and CRN initiated")
    except Exception as e:
        await client.close()
        echo(f"Failed to initiate confidential session with VM and CRN, reason:\n{e}")
        return 1
    await client.close()


@app.command()
async def confidential_start(
    vm_id: str = typer.Argument(..., help="VM item hash to start"),
    domain: Optional[str] = typer.Option(None, help="CRN domain on which the VM will be started"),
    chain: Optional[Chain] = typer.Option(None, help=help_strings.PAYMENT_CHAIN_USED, metavar=metavar_valid_chains),
    firmware_hash: str = typer.Option(
        settings.DEFAULT_CONFIDENTIAL_FIRMWARE_HASH, help=help_strings.CONFIDENTIAL_FIRMWARE_HASH
    ),
    firmware_file: str = typer.Option(None, help=help_strings.CONFIDENTIAL_FIRMWARE_PATH),
    vm_secret: str = typer.Option(None, help=help_strings.VM_SECRET),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    verbose: bool = typer.Option(True),
    debug: bool = False,
):
    """Validate the authenticity of the VM and start it"""

    setup_logging(debug)

    assert settings.CONFIG_HOME
    session_dir = Path(settings.CONFIG_HOME) / "confidential_sessions" / vm_id
    session_dir.mkdir(exist_ok=True, parents=True)

    vm_hash = ItemHash(vm_id)
    account = _load_account(private_key, private_key_file, chain=chain)
    sevctl_path = find_sevctl_or_exit()

    domain = (
        (domain and sanitize_url(domain))
        or await find_crn_of_vm(vm_id)
        or Prompt.ask("URL of the CRN (Compute node) on which the VM will be started")
    )

    client = VmConfidentialClient(account, sevctl_path, domain)

    if not session_dir.exists():
        echo("Please run confidential-init-session first ")
        return 1

    try:
        sev_data = await client.measurement(vm_hash)
        echo("Retrieved measurement")
    except Exception as e:
        await client.close()
        echo(f"Failed to start the VM, reason:\n{e}")
        return 1

    tek_path = session_dir / "vm_tek.bin"
    tik_path = session_dir / "vm_tik.bin"

    if firmware_file:
        firmware_path = Path(firmware_file)
        if not firmware_path.exists():
            msg = "Firmware path does not exist"
            raise FileNotFoundError(msg)
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
    try:
        await client.inject_secret(vm_hash, encoded_packet_header, encoded_secret)
    except Exception as e:
        await client.close()
        echo(f"Failed to start the VM, reason:\n{e}")
        return 1
    await client.close()

    console = Console()
    infos = [Text.from_markup(f"Your instance [bright_cyan]{vm_id}[/bright_cyan] is currently starting.")]
    if verbose:
        infos += [
            Text.assemble(
                "\n\nTo get your instance's IPv6, check out:\n",
                Text.assemble(
                    "↳ aleph instance list",
                    style="italic",
                ),
                "\n\nTo access your instance's logs, use:\n",
                Text.from_markup(
                    f"↳ aleph instance logs [bright_cyan]{vm_id}[/bright_cyan]",
                    style="italic",
                ),
            )
        ]
    console.print(
        Panel(Text.assemble(*infos), title="Instance Started", border_style="green", expand=False, title_align="left")
    )


@app.command(name="confidential")
async def confidential_create(
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
    firmware_file: Optional[str] = typer.Option(None, help=help_strings.CONFIDENTIAL_FIRMWARE_PATH),
    keep_session: Optional[bool] = typer.Option(None, help=help_strings.KEEP_SESSION),
    vm_secret: Optional[str] = typer.Option(None, help=help_strings.VM_SECRET),
    payment_type: Optional[str] = typer.Option(
        None,
        help=help_strings.PAYMENT_TYPE,
        callback=lambda pt: None if pt is None else pt.lower(),
        metavar=metavar_valid_payment_types,
        case_sensitive=False,
    ),
    payment_chain: Optional[Chain] = typer.Option(
        None,
        help=help_strings.PAYMENT_CHAIN,
        metavar=metavar_valid_chains,
        case_sensitive=False,
    ),
    name: Optional[str] = typer.Option(None, help=help_strings.INSTANCE_NAME),
    rootfs: Optional[str] = typer.Option(None, help=help_strings.ROOTFS),
    compute_units: Optional[int] = typer.Option(None, help=help_strings.COMPUTE_UNITS),
    vcpus: Optional[int] = typer.Option(None, help=help_strings.VCPUS),
    memory: Optional[int] = typer.Option(None, help=help_strings.MEMORY),
    rootfs_size: Optional[int] = typer.Option(None, help=help_strings.ROOTFS_SIZE),
    timeout_seconds: float = typer.Option(
        settings.DEFAULT_VM_TIMEOUT,
        help=help_strings.TIMEOUT_SECONDS,
    ),
    ssh_pubkey_file: Path = typer.Option(
        Path("~/.ssh/id_rsa.pub").expanduser(),
        help=help_strings.SSH_PUBKEY_FILE,
    ),
    address: Optional[str] = typer.Option(None, help=help_strings.ADDRESS_PAYER),
    gpu: bool = typer.Option(False, help=help_strings.GPU_OPTION),
    premium: Optional[bool] = typer.Option(None, help=help_strings.GPU_PREMIUM_OPTION),
    skip_volume: bool = typer.Option(False, help=help_strings.SKIP_VOLUME),
    persistent_volume: Optional[list[str]] = typer.Option(None, help=help_strings.PERSISTENT_VOLUME),
    ephemeral_volume: Optional[list[str]] = typer.Option(None, help=help_strings.EPHEMERAL_VOLUME),
    immutable_volume: Optional[list[str]] = typer.Option(
        None,
        help=help_strings.IMMUTABLE_VOLUME,
    ),
    crn_auto_tac: bool = typer.Option(False, help=help_strings.CRN_AUTO_TAC),
    channel: Optional[str] = typer.Option(default=settings.DEFAULT_CHANNEL, help=help_strings.CHANNEL),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    """Create (optional), start and unlock a confidential VM (all-in-one command)

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
        vm_id, crn_url, payment_chain = await create(
            payment_type=payment_type,
            payment_chain=payment_chain,
            hypervisor=HypervisorType.qemu,
            name=name,
            rootfs=rootfs,
            compute_units=compute_units,
            vcpus=vcpus,
            memory=memory,
            rootfs_size=rootfs_size,
            timeout_seconds=timeout_seconds,
            ssh_pubkey_file=ssh_pubkey_file,
            address=address,
            crn_hash=crn_hash,
            crn_url=crn_url,
            crn_auto_tac=crn_auto_tac,
            confidential=True,
            confidential_firmware=confidential_firmware,
            gpu=gpu,
            premium=premium,
            skip_volume=skip_volume,
            persistent_volume=persistent_volume,
            ephemeral_volume=ephemeral_volume,
            immutable_volume=immutable_volume,
            channel=channel,
            private_key=private_key,
            private_key_file=private_key_file,
            print_message=False,
            verbose=False,
            debug=debug,
        )
        if not vm_id or len(vm_id) != 64:
            echo("Could not create the VM")
            return 1
        allocated = vm_id is not None
    elif vm_id and not payment_chain:
        async with AlephHttpClient(api_server=settings.API_HOST) as client:
            try:
                existing_message: InstanceMessage = await client.get_message(
                    item_hash=ItemHash(vm_id), message_type=InstanceMessage
                )
                payment_chain = existing_message.content.payment.chain  # type: ignore
            except MessageNotFoundError as error:
                echo("Instance does not exist")
                raise typer.Exit(code=1) from error
            except ForgottenMessageError as error:
                echo("Instance already forgotten")
                raise typer.Exit(code=1) from error

    crn_url = (
        (crn_url and sanitize_url(crn_url)) or await find_crn_of_vm(vm_id) or Prompt.ask(help_strings.PROMPT_CRN_URL)
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
            chain=payment_chain,
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

    # Safe delay to ensure instance is starting and is ready
    echo("Waiting 10sec before to start...")
    await asyncio.sleep(10)

    await confidential_start(
        vm_id=vm_id,
        domain=crn_url,
        chain=payment_chain,
        firmware_hash=firmware_hash,
        firmware_file=firmware_file,
        vm_secret=vm_secret,
        private_key=private_key,
        private_key_file=private_key_file,
        verbose=True,
        debug=debug,
    )


@app.command(name="gpu")
async def gpu_create(
    payment_chain: Optional[Chain] = typer.Option(
        None,
        help=help_strings.PAYMENT_CHAIN,
        metavar=metavar_valid_payg_chains,
        case_sensitive=False,
    ),
    name: Optional[str] = typer.Option(None, help=help_strings.INSTANCE_NAME),
    rootfs: Optional[str] = typer.Option(None, help=help_strings.ROOTFS),
    compute_units: Optional[int] = typer.Option(None, help=help_strings.COMPUTE_UNITS),
    vcpus: Optional[int] = typer.Option(None, help=help_strings.VCPUS),
    memory: Optional[int] = typer.Option(None, help=help_strings.MEMORY),
    rootfs_size: Optional[int] = typer.Option(None, help=help_strings.ROOTFS_SIZE),
    premium: Optional[bool] = typer.Option(None, help=help_strings.GPU_PREMIUM_OPTION),
    timeout_seconds: float = typer.Option(
        settings.DEFAULT_VM_TIMEOUT,
        help=help_strings.TIMEOUT_SECONDS,
    ),
    ssh_pubkey_file: Path = typer.Option(
        Path("~/.ssh/id_rsa.pub").expanduser(),
        help=help_strings.SSH_PUBKEY_FILE,
    ),
    address: Optional[str] = typer.Option(None, help=help_strings.ADDRESS_PAYER),
    crn_hash: Optional[str] = typer.Option(None, help=help_strings.CRN_HASH),
    crn_url: Optional[str] = typer.Option(None, help=help_strings.CRN_URL),
    skip_volume: bool = typer.Option(False, help=help_strings.SKIP_VOLUME),
    persistent_volume: Optional[list[str]] = typer.Option(None, help=help_strings.PERSISTENT_VOLUME),
    ephemeral_volume: Optional[list[str]] = typer.Option(None, help=help_strings.EPHEMERAL_VOLUME),
    immutable_volume: Optional[list[str]] = typer.Option(
        None,
        help=help_strings.IMMUTABLE_VOLUME,
    ),
    crn_auto_tac: bool = typer.Option(False, help=help_strings.CRN_AUTO_TAC),
    channel: Optional[str] = typer.Option(default=settings.DEFAULT_CHANNEL, help=help_strings.CHANNEL),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    print_message: bool = typer.Option(False),
    verbose: bool = typer.Option(True),
    debug: bool = False,
):
    """Create and register a new GPU instance on aleph.im"""

    await create(
        payment_type=PaymentType.superfluid,
        payment_chain=payment_chain,
        hypervisor=HypervisorType.qemu,
        name=name,
        rootfs=rootfs,
        compute_units=compute_units,
        vcpus=vcpus,
        memory=memory,
        rootfs_size=rootfs_size,
        timeout_seconds=timeout_seconds,
        ssh_pubkey_file=ssh_pubkey_file,
        address=address,
        crn_hash=crn_hash,
        crn_url=crn_url,
        crn_auto_tac=crn_auto_tac,
        confidential=False,
        confidential_firmware=None,
        gpu=True,
        premium=premium,
        skip_volume=skip_volume,
        persistent_volume=persistent_volume,
        ephemeral_volume=ephemeral_volume,
        immutable_volume=immutable_volume,
        channel=channel,
        private_key=private_key,
        private_key_file=private_key_file,
        print_message=print_message,
        verbose=verbose,
        debug=debug,
    )
