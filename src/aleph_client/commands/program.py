from __future__ import annotations

import json
import logging
import re
from base64 import b16decode, b32encode
from collections.abc import Mapping
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Any, Optional, Union, cast
from zipfile import BadZipFile

import aiohttp
import typer
from aleph.sdk import AlephHttpClient, AuthenticatedAlephHttpClient
from aleph.sdk.account import _load_account
from aleph.sdk.client.vm_client import VmClient
from aleph.sdk.conf import load_main_configuration, settings
from aleph.sdk.evm_utils import get_chains_with_holding
from aleph.sdk.exceptions import (
    ForgottenMessageError,
    InsufficientFundsError,
    MessageNotFoundError,
)
from aleph.sdk.query.filters import MessageFilter
from aleph.sdk.query.responses import PriceResponse
from aleph.sdk.types import AccountFromPrivateKey, StorageEnum, TokenType
from aleph.sdk.utils import displayable_amount, make_program_content, safe_getattr
from aleph_message.models import (
    Chain,
    MessageType,
    Payment,
    PaymentType,
    ProgramMessage,
    StoreMessage,
)
from aleph_message.models.execution.program import ProgramContent
from aleph_message.models.item_hash import ItemHash
from aleph_message.status import MessageStatus
from click import echo
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from aleph_client.commands import help_strings
from aleph_client.commands.account import get_balance
from aleph_client.commands.pricing import PricingEntity, SelectedTier, fetch_pricing
from aleph_client.commands.utils import (
    display_mounted_volumes,
    filter_only_valid_messages,
    get_or_prompt_environment_variables,
    get_or_prompt_volumes,
    input_multiline,
    setup_logging,
    str_to_datetime,
    validated_prompt,
    yes_no_input,
)
from aleph_client.utils import AsyncTyper, create_archive, sanitize_url

logger = logging.getLogger(__name__)
app = AsyncTyper(no_args_is_help=True)

hold_chains = [*get_chains_with_holding(), Chain.SOL]
metavar_valid_chains = f"[{'|'.join(hold_chains)}]"


@app.command(name="upload")
@app.command(name="create")
async def upload(
    path: Annotated[Path, typer.Argument(help=help_strings.PROGRAM_PATH)],
    entrypoint: Annotated[str, typer.Argument(help=help_strings.PROGRAM_ENTRYPOINT)],
    name: Annotated[Optional[str], typer.Option(help="Name for your program")] = None,
    runtime: Annotated[
        Optional[str], typer.Option(help=help_strings.PROGRAM_RUNTIME.format(runtime_id=settings.DEFAULT_RUNTIME_ID))
    ] = None,
    compute_units: Annotated[Optional[int], typer.Option(help=help_strings.COMPUTE_UNITS)] = None,
    vcpus: Annotated[Optional[int], typer.Option(help=help_strings.VCPUS)] = None,
    memory: Annotated[Optional[int], typer.Option(help=help_strings.MEMORY)] = None,
    timeout_seconds: Annotated[float, typer.Option(help=help_strings.TIMEOUT_SECONDS)] = settings.DEFAULT_VM_TIMEOUT,
    internet: Annotated[bool, typer.Option(help=help_strings.PROGRAM_INTERNET)] = False,
    updatable: Annotated[bool, typer.Option(help=help_strings.PROGRAM_UPDATABLE)] = False,
    beta: Annotated[bool, typer.Option(help=help_strings.PROGRAM_BETA)] = False,
    persistent: Annotated[bool, typer.Option(help=help_strings.PROGRAM_PERSISTENT)] = False,
    skip_volume: Annotated[bool, typer.Option(help=help_strings.SKIP_VOLUME)] = False,
    persistent_volume: Annotated[Optional[list[str]], typer.Option(help=help_strings.PERSISTENT_VOLUME)] = None,
    ephemeral_volume: Annotated[Optional[list[str]], typer.Option(help=help_strings.EPHEMERAL_VOLUME)] = None,
    immutable_volume: Annotated[Optional[list[str]], typer.Option(help=help_strings.IMMUTABLE_VOLUME)] = None,
    skip_env_var: Annotated[bool, typer.Option(help=help_strings.SKIP_ENV_VAR)] = False,
    env_vars: Annotated[Optional[str], typer.Option(help=help_strings.ENVIRONMENT_VARIABLES)] = None,
    address: Annotated[Optional[str], typer.Option(help=help_strings.ADDRESS_PAYER)] = None,
    payment_chain: Annotated[
        Optional[Chain],
        typer.Option(
            help=help_strings.PAYMENT_CHAIN_PROGRAM,
            metavar=metavar_valid_chains,
            case_sensitive=False,
        ),
    ] = None,
    channel: Annotated[Optional[str], typer.Option(help=help_strings.CHANNEL)] = settings.DEFAULT_CHANNEL,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    print_messages: Annotated[bool, typer.Option(help="Print the messages after creation")] = False,
    print_code_message: Annotated[bool, typer.Option(help="Print the code message after creation")] = False,
    print_program_message: Annotated[bool, typer.Option(help="Print the program message after creation")] = False,
    verbose: Annotated[bool, typer.Option(help="Display additional information")] = True,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
) -> Optional[str]:
    """Register a program to run on aleph.im (create/upload are aliases)

    For more information, see https://docs.aleph.im/computing"""

    setup_logging(debug)
    console = Console()
    path = path.absolute()

    try:
        path_object, encoding = create_archive(path)
    except BadZipFile as error:
        typer.echo("Invalid zip archive")
        raise typer.Exit(code=3) from error
    except FileNotFoundError as error:
        typer.echo("No such file or directory")
        raise typer.Exit(code=4) from error

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file, chain=payment_chain)
    address = address or settings.ADDRESS_TO_USE or account.get_address()

    # Loads default configuration if no chain is set
    if payment_chain is None:
        config = load_main_configuration(settings.CONFIG_FILE)
        if config is not None:
            payment_chain = config.chain
            console.print(f"Preset to default chain: [green]{payment_chain}[/green]")
        else:
            payment_chain = Chain.ETH
            console.print("No active chain selected in configuration. Fallback to ETH")

    payment = Payment(
        chain=payment_chain,
        receiver=None,
        type=PaymentType.hold,
    )

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        # Upload the source code
        with open(path_object, "rb") as fd:
            logger.debug("Reading file")
            # TODO: Read in lazy mode instead of copying everything in memory
            file_content = fd.read()
            storage_engine = StorageEnum.ipfs if len(file_content) > 4 * 1024 * 1024 else StorageEnum.storage
            logger.debug("Uploading file")
            user_code: StoreMessage
            status: MessageStatus
            user_code, status = await client.create_store(
                file_content=file_content,
                storage_engine=storage_engine,
                channel=channel,
                guess_mime_type=True,
                ref=None,
            )
            logger.debug("Code upload finished")
            if print_messages or print_code_message:
                typer.echo(f"{user_code.model_dump_json(indent=4)}")
            program_ref = user_code.item_hash

        pricing = await fetch_pricing()
        pricing_entity = PricingEntity.PROGRAM_PERSISTENT if persistent else PricingEntity.PROGRAM
        tier = cast(  # Safe cast
            SelectedTier,
            pricing.display_table_for(
                pricing_entity,
                compute_units=compute_units,
                vcpus=vcpus,
                memory=memory,
                selector=True,
                verbose=verbose,
            ),
        )
        name = name or validated_prompt("Program name", lambda x: x and len(x) < 65)
        vcpus = tier.vcpus
        memory = tier.memory
        runtime = runtime or input(f"Ref of runtime? [{settings.DEFAULT_RUNTIME_ID}] ") or settings.DEFAULT_RUNTIME_ID

        volumes = []
        if any([persistent_volume, ephemeral_volume, immutable_volume]) or not skip_volume:
            volumes = get_or_prompt_volumes(
                persistent_volume=persistent_volume,
                ephemeral_volume=ephemeral_volume,
                immutable_volume=immutable_volume,
            )

        environment_variables = None
        if not skip_env_var:
            environment_variables = get_or_prompt_environment_variables(env_vars)

        subscriptions: Optional[list[Mapping]] = None
        if beta and yes_no_input("Subscribe to messages?", default=False):
            content_raw = input_multiline()
            try:
                subscriptions = json.loads(content_raw)
            except json.decoder.JSONDecodeError as error:
                typer.echo("Not valid JSON")
                raise typer.Exit(code=2) from error
        else:
            subscriptions = None

        content_dict: dict[str, Any] = {
            "program_ref": program_ref,
            "entrypoint": entrypoint,
            "runtime": runtime,
            "metadata": {"name": name},
            "address": address,
            "payment": payment,
            "vcpus": vcpus,
            "memory": memory,
            "timeout_seconds": timeout_seconds,
            "internet": internet,
            "allow_amend": updatable,
            "encoding": encoding,
            "persistent": persistent,
            "volumes": volumes,
            "environment_variables": environment_variables,
            "subscriptions": subscriptions,
        }

        # Estimate cost and check required balances (Aleph ERC20)
        required_tokens: Decimal
        try:
            content = make_program_content(**content_dict)
            price: PriceResponse = await client.get_estimated_price(content)
            required_tokens = Decimal(price.required_tokens)
        except Exception as e:
            typer.echo(f"Failed to estimate program cost, error: {e}")
            raise typer.Exit(code=1) from e

        available_funds = Decimal((await get_balance(address))["available_amount"])
        try:
            if available_funds < required_tokens:
                raise InsufficientFundsError(TokenType.ALEPH, float(required_tokens), float(available_funds))
        except InsufficientFundsError as e:
            typer.echo(e)
            raise typer.Exit(code=1) from e

        # Register the program
        try:
            message, status = await client.create_program(
                **content_dict,
                channel=channel,
                storage_engine=StorageEnum.storage,
                sync=True,
            )
        except InsufficientFundsError as e:
            typer.echo(
                f"Program creation failed due to insufficient funds.\n"
                f"{address} has {e.available_funds} ALEPH but needs {e.required_funds} ALEPH."
            )
            raise typer.Exit(code=1) from e

        logger.debug("Program upload finished")
        if print_messages or print_program_message:
            typer.echo(f"{message.model_dump_json(indent=4)}")

        item_hash: ItemHash = message.item_hash
        if verbose:
            hash_base32 = b32encode(b16decode(item_hash.upper())).strip(b"=").lower().decode()
            func_url_1 = f"{settings.VM_URL_PATH.format(hash=item_hash)}"
            func_url_2 = f"{settings.VM_URL_HOST.format(hash_base32=hash_base32)}"
            infos = [
                Text.from_markup(f"Your program [bright_cyan]{item_hash}[/bright_cyan] has been uploaded on aleph.im."),
                Text.assemble(
                    "\n\nAvailable on:\n",
                    Text.from_markup(
                        f"↳ [bright_yellow][link={func_url_1}]{func_url_1}[/link][/bright_yellow]\n",
                        style="italic",
                    ),
                    Text.from_markup(
                        f"↳ [dark_olive_green2][link={func_url_2}]{func_url_2}[/link][/dark_olive_green2]",
                        style="italic",
                    ),
                    "\n\nVisualise on:\n",
                    Text.from_markup(
                        f"[blue]https://explorer.aleph.im/address/{message.chain.value}/{message.sender}/message/PROGRAM/{item_hash}[/blue]"
                    ),
                ),
            ]
            console.print(
                Panel(
                    Text.assemble(*infos),
                    title="Program Created",
                    border_style="green",
                    expand=False,
                    title_align="left",
                )
            )
        return item_hash


@app.command()
async def update(
    item_hash: Annotated[str, typer.Argument(help="Item hash to update")],
    path: Annotated[Path, typer.Argument(help=help_strings.PROGRAM_PATH)],
    chain: Annotated[
        Optional[Chain], typer.Option(help=help_strings.PAYMENT_CHAIN_PROGRAM_USED, metavar=metavar_valid_chains)
    ] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    print_message: Annotated[bool, typer.Option(help="Print the message after creation")] = False,
    verbose: Annotated[bool, typer.Option(help="Display additional information")] = True,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
):
    """Update the code of an existing program (item hash will not change)"""

    setup_logging(debug)

    path = path.absolute()

    try:
        path_object, encoding = create_archive(path)
    except BadZipFile as error:
        typer.echo("Invalid zip archive")
        raise typer.Exit(code=3) from error
    except FileNotFoundError as error:
        typer.echo("No such file or directory")
        raise typer.Exit(code=4) from error

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file, chain=chain)

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        try:
            program_message: ProgramMessage = await client.get_message(item_hash=item_hash, message_type=ProgramMessage)
        except MessageNotFoundError:
            typer.echo("Program does not exist on aleph.im")
            return 1
        except ForgottenMessageError:
            typer.echo("Program has been deleted on aleph.im")
            return 1
        if program_message.sender != account.get_address():
            typer.echo("You are not the owner of this program")
            return 1

        code_ref = program_message.content.code.ref
        try:
            code_message: StoreMessage = await client.get_message(item_hash=code_ref, message_type=StoreMessage)
        except MessageNotFoundError:
            typer.echo("Code volume does not exist on aleph.im")
            return 1
        except ForgottenMessageError:
            typer.echo("Code volume has been deleted on aleph.im")
            return 1
        if encoding != program_message.content.code.encoding:
            logger.error(
                f"Code must be encoded with the same encoding as the previous version "
                f"('{encoding}' vs '{program_message.content.code.encoding}'"
            )
            return 1

        # Upload the new source code
        with open(path_object, "rb") as fd:
            logger.debug("Reading file")
            # TODO: Read in lazy mode instead of copying everything in memory
            file_content = fd.read()
            logger.debug("Uploading file")
            message: StoreMessage
            message, status = await client.create_store(
                file_content=file_content,
                storage_engine=StorageEnum(code_message.content.item_type),
                channel=code_message.channel,
                guess_mime_type=True,
                ref=code_message.item_hash,
            )
            logger.debug("Code upload finished")
            if print_message:
                typer.echo(f"{message.model_dump_json(indent=4)}")

        if verbose:
            hash_base32 = b32encode(b16decode(item_hash.upper())).strip(b"=").lower().decode()
            func_url_1 = f"{settings.VM_URL_PATH.format(hash=item_hash)}"
            func_url_2 = f"{settings.VM_URL_HOST.format(hash_base32=hash_base32)}"
            console = Console()
            infos = [
                Text.from_markup(
                    f"Your program [bright_cyan]{item_hash}[/bright_cyan] has been updated to the new source code."
                ),
                Text.from_markup(f"\n\nUpdated code volume: [orange3]{code_message.item_hash}[/orange3]"),
                Text.assemble(
                    "\n\nAvailable on:\n",
                    Text.from_markup(
                        f"↳ [bright_yellow][link={func_url_1}]{func_url_1}[/link][/bright_yellow]\n",
                        style="italic",
                    ),
                    Text.from_markup(
                        f"↳ [dark_olive_green2][link={func_url_2}]{func_url_2}[/link][/dark_olive_green2]",
                        style="italic",
                    ),
                ),
            ]
            console.print(
                Panel(
                    Text.assemble(*infos),
                    title="Program Updated",
                    border_style="orange3",
                    expand=False,
                    title_align="left",
                )
            )


@app.command()
async def delete(
    item_hash: Annotated[str, typer.Argument(help="Item hash to unpersist")],
    reason: Annotated[str, typer.Option(help="Reason for deleting the program")] = "User deletion",
    keep_code: Annotated[bool, typer.Option(help=help_strings.PROGRAM_KEEP_CODE)] = False,
    chain: Annotated[
        Optional[Chain], typer.Option(help=help_strings.PAYMENT_CHAIN_PROGRAM_USED, metavar=metavar_valid_chains)
    ] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    print_message: Annotated[bool, typer.Option(help="Print the message after deletion")] = False,
    verbose: Annotated[bool, typer.Option(help="Display additional information")] = True,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
):
    """Delete a program"""

    setup_logging(debug)

    account = _load_account(private_key, private_key_file, chain=chain)

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        try:
            existing_message: ProgramMessage = await client.get_message(
                item_hash=item_hash, message_type=ProgramMessage
            )
        except MessageNotFoundError:
            typer.echo("Program does not exist on aleph.im")
            return 1
        except ForgottenMessageError:
            typer.echo("Program has been already deleted on aleph.im")
            return 1
        if existing_message.sender != account.get_address():
            typer.echo("You are not the owner of this program")
            return 1

        message, _ = await client.forget(hashes=[ItemHash(item_hash)], reason=reason)
        if not keep_code:
            try:
                code_volume: StoreMessage = await client.get_message(
                    item_hash=existing_message.content.code.ref, message_type=StoreMessage
                )
            except MessageNotFoundError:
                typer.echo("Code volume does not exist. Skipping...")
                return 1
            except ForgottenMessageError:
                typer.echo("Code volume has been already deleted. Skipping...")
                return 1
            if existing_message.sender != account.get_address():
                typer.echo("You are not the owner of this code volume. Skipping...")
                return 1

            code_message, _ = await client.forget(
                hashes=[ItemHash(code_volume.item_hash)], reason=f"Deletion of program {item_hash}"
            )
            if verbose:
                typer.echo(f"Code volume {code_volume.item_hash} has been deleted.")
        if print_message:
            typer.echo(f"{message.json(indent=4)}")
        if verbose:
            typer.echo(f"Program {item_hash} has been deleted.")


@app.command(name="list")
async def list_programs(
    address: Annotated[Optional[str], typer.Option(help="Owner address of the programs")] = None,
    chain: Annotated[
        Optional[Chain], typer.Option(help=help_strings.ADDRESS_CHAIN, metavar=metavar_valid_chains)
    ] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    json: Annotated[bool, typer.Option(help="Print as json instead of rich table")] = False,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
):
    """List all programs associated to an account"""

    setup_logging(debug)

    account = _load_account(private_key, private_key_file, chain=chain)
    address = address or settings.ADDRESS_TO_USE or account.get_address()

    async with AlephHttpClient(api_server=settings.API_HOST) as client:
        resp = await client.get_messages(
            message_filter=MessageFilter(
                message_types=[MessageType.program],
                addresses=[address],
            ),
            page_size=100,
        )
        messages = await filter_only_valid_messages(resp.messages)
        if not messages:
            typer.echo(f"Address: {address}\n\nNo program found\n")
            raise typer.Exit(code=1)

        if json:
            for message in messages:
                typer.echo(message.json(indent=4))
            return

        # Since we filtered on message type, we can safely cast as ProgramMessage.
        messages = cast(list[ProgramMessage], messages)

        table = Table(box=box.ROUNDED, style="blue_violet")
        table.add_column(f"Programs [{len(messages)}]", style="blue", overflow="fold")
        table.add_column("Specifications", style="blue")
        table.add_column("Configurations", style="blue", overflow="fold")

        for message in messages:
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
            msg_link = f"https://explorer.aleph.im/address/ETH/{message.sender}/message/PROGRAM/{message.item_hash}"
            item_hash_link = Text.from_markup(f"[link={msg_link}]{message.item_hash}[/link]", style="bright_cyan")
            payment_type = safe_getattr(message.content, "payment.type", PaymentType.hold)
            payment = Text.assemble(
                "Payment: ",
                Text(
                    payment_type.capitalize().ljust(12),
                    style="red" if payment_type == PaymentType.hold else "orange3",
                ),
            )
            persistent = Text.assemble(
                "Type: ",
                (
                    Text("Persistent", style="green")
                    if message.content.on.persistent
                    else Text("Ephemeral", style="grey50")
                ),
            )
            payment_chain = str(safe_getattr(message.content, "payment.chain.value") or Chain.ETH.value)
            if payment_chain != Chain.SOL.value:
                payment_chain = "EVM"
            pay_chain = Text.assemble("Chain: ", Text(payment_chain.ljust(14), style="white"))
            created_at = Text.assemble(
                "Created at: ",
                Text(
                    str(str_to_datetime(str(safe_getattr(message, "content.time")))).split(".", maxsplit=1)[0],
                    style="orchid",
                ),
            )
            payer: Union[str, Text] = ""
            if message.sender != message.content.address:
                payer = Text.assemble("\nPayer: ", Text(str(message.content.address), style="orange1"))
            price: PriceResponse = await client.get_program_price(message.item_hash)
            required_tokens = Decimal(price.required_tokens)
            if price.payment_type == PaymentType.hold.value:
                aleph_price = Text(
                    f"{displayable_amount(required_tokens, decimals=3)} (fixed)".ljust(13), style="violet"
                )
            else:
                # PAYG not implemented yet for programs
                aleph_price = Text("")
            cost = Text.assemble("\n$ALEPH: ", aleph_price)
            hash_base32 = b32encode(b16decode(message.item_hash.upper())).strip(b"=").lower().decode()
            func_url_1 = settings.VM_URL_PATH.format(hash=message.item_hash)
            func_url_2 = settings.VM_URL_HOST.format(hash_base32=hash_base32)
            urls = Text.from_markup(
                f"URLs ↓\n[bright_yellow][link={func_url_1}]{func_url_1}[/link][/bright_yellow]"
                f"\n[dark_olive_green2][link={func_url_2}]{func_url_2}[/link][/dark_olive_green2]"
            )
            program = Text.assemble(
                "Item Hash ↓\t     Name: ",
                name,
                "\n",
                item_hash_link,
                "\n",
                payment,
                persistent,
                "\n",
                pay_chain,
                created_at,
                payer,
                cost,
                urls,
            )
            specs = [
                f"vCPU: [magenta3]{message.content.resources.vcpus}[/magenta3]\n",
                f"RAM: [magenta3]{message.content.resources.memory / 1_024:.2f} GiB[/magenta3]\n",
                "HyperV: [magenta3]Firecracker[/magenta3]\n",
                f"Timeout: [orange3]{message.content.resources.seconds}s[/orange3]\n",
                f"Internet: {'[green]Yes[/green]' if message.content.environment.internet else '[red]No[/red]'}\n",
                f"Updatable: {'[green]Yes[/green]' if message.content.allow_amend else '[orange3]Code only[/orange3]'}",
            ]
            specifications = Text.from_markup("".join(specs))
            config = Text.assemble(
                Text.from_markup(
                    f"Runtime: [bright_cyan][link={settings.API_HOST}/api/v0/messages/{message.content.runtime.ref}]"
                    f"{message.content.runtime.ref}[/link][/bright_cyan]\n"
                    f"Code: [bright_cyan][link={settings.API_HOST}/api/v0/messages/{message.content.code.ref}]"
                    f"{message.content.code.ref}[/link][/bright_cyan]\n"
                    f"↳ Entrypoint: [orchid]{message.content.code.entrypoint}[/orchid]\n"
                ),
                Text.from_markup(display_mounted_volumes(message)),
            )
            table.add_row(program, specifications, config)
            table.add_section()

        console = Console()
        console.print(table)
        infos = [
            Text.from_markup(
                f"[bold]Address:[/bold] [bright_cyan]{messages[0].sender}[/bright_cyan]\n\nTo access any "
                "program's logs, use:\n"
            ),
            Text.from_markup(
                "↳ aleph program logs [bright_cyan]<program-item-hash>[/bright_cyan] --domain [orchid]<crn-url>"
                "[/orchid]",
                style="italic",
            ),
        ]
        console.print(
            Panel(Text.assemble(*infos), title="Infos", border_style="bright_cyan", expand=False, title_align="left")
        )


@app.command()
async def persist(
    item_hash: Annotated[str, typer.Argument(help="Item hash to persist")],
    keep_prev: Annotated[bool, typer.Option(help=help_strings.PROGRAM_KEEP_PREV)] = False,
    chain: Annotated[
        Optional[Chain], typer.Option(help=help_strings.PAYMENT_CHAIN_PROGRAM_USED, metavar=metavar_valid_chains)
    ] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    print_message: Annotated[bool, typer.Option(help="Print the message after persisting")] = False,
    verbose: Annotated[bool, typer.Option(help="Display additional information")] = True,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
) -> Optional[str]:
    """
    Recreate a non-persistent program as persistent (item hash will change). The program must be updatable and yours
    """

    setup_logging(debug)

    account = _load_account(private_key, private_key_file, chain=chain)

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        try:
            message: ProgramMessage = await client.get_message(item_hash=item_hash, message_type=ProgramMessage)
        except MessageNotFoundError:
            typer.echo("Program does not exist on aleph.im")
            return None
        except ForgottenMessageError:
            typer.echo("Program has been deleted on aleph.im")
            return None
        if message.sender != account.get_address():
            typer.echo("You are not the owner of this program")
            return None
        if not message.content.allow_amend:
            typer.echo("Program is not updatable")
            return None
        if message.content.on.persistent:
            typer.echo("Program is already persistent")
            return None

        # Update content
        content: ProgramContent = message.content.model_copy()
        content.on.persistent = True
        content.replaces = message.item_hash

        message, _status, _ = await client.submit(
            content=content.model_dump(exclude_none=True),
            message_type=message.type,
            channel=message.channel,
        )

        if print_message:
            typer.echo(f"{message.json(indent=4)}")

        # Delete previous non-persistent program
        prev_label, prev_color = "INTACT", "orange3"
        if not keep_prev:
            await client.forget(hashes=[ItemHash(item_hash)], reason="Program persisted")
            prev_label, prev_color = "DELETED", "red"

        if verbose:
            hash_base32 = b32encode(b16decode(item_hash.upper())).strip(b"=").lower().decode()
            func_url_1 = f"{settings.VM_URL_PATH.format(hash=item_hash)}"
            func_url_2 = f"{settings.VM_URL_HOST.format(hash_base32=hash_base32)}"
            console = Console()
            infos = [
                Text.from_markup("Your program is now [green]persistent[/green]. It implies a new item hash."),
                Text.from_markup(
                    f"\n\n[{prev_color}]- Prev non-persistent program: {item_hash} ➜ {prev_label}[/{prev_color}]\n"
                    f"[green]- New persistent program: {message.item_hash}[/green]."
                ),
                Text.assemble(
                    "\n\nAvailable on:\n",
                    Text.from_markup(
                        f"↳ [bright_yellow][link={func_url_1}]{func_url_1}[/link][/bright_yellow]\n",
                        style="italic",
                    ),
                    Text.from_markup(
                        f"↳ [dark_olive_green2][link={func_url_2}]{func_url_2}[/link][/dark_olive_green2]",
                        style="italic",
                    ),
                ),
            ]
            console.print(
                Panel(
                    Text.assemble(*infos),
                    title="Program: Persist",
                    border_style="orchid",
                    expand=False,
                    title_align="left",
                )
            )
        return message.item_hash


@app.command()
async def unpersist(
    item_hash: Annotated[str, typer.Argument(help="Item hash to unpersist")],
    keep_prev: Annotated[bool, typer.Option(help=help_strings.PROGRAM_KEEP_PREV)] = False,
    chain: Annotated[
        Optional[Chain], typer.Option(help=help_strings.PAYMENT_CHAIN_PROGRAM_USED, metavar=metavar_valid_chains)
    ] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    print_message: Annotated[bool, typer.Option(help="Print the message after unpersisting")] = False,
    verbose: Annotated[bool, typer.Option(help="Display additional information")] = True,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
) -> Optional[str]:
    """
    Recreate a persistent program as non-persistent (item hash will change). The program must be updatable and yours
    """

    setup_logging(debug)

    account = _load_account(private_key, private_key_file, chain=chain)

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        try:
            message: ProgramMessage = await client.get_message(item_hash=item_hash, message_type=ProgramMessage)
        except MessageNotFoundError:
            typer.echo("Program does not exist on aleph.im")
            return None
        except ForgottenMessageError:
            typer.echo("Program has been deleted on aleph.im")
            return None
        if message.sender != account.get_address():
            typer.echo("You are not the owner of this program")
            return None
        if not message.content.allow_amend:
            typer.echo("Program is not updatable")
            return None
        if not message.content.on.persistent:
            typer.echo("Program is already unpersistent")
            return None

        # Update content
        content: ProgramContent = message.content.model_copy()
        content.on.persistent = False
        content.replaces = message.item_hash

        message, _status, _ = await client.submit(
            content=content.model_dump(exclude_none=True),
            message_type=message.type,
            channel=message.channel,
        )

        if print_message:
            typer.echo(f"{message.json(indent=4)}")

        # Delete previous persistent program
        prev_label, prev_color = "INTACT", "orange3"
        if not keep_prev:
            await client.forget(hashes=[ItemHash(item_hash)], reason="Program unpersisted")
            prev_label, prev_color = "DELETED", "red"

        if verbose:
            hash_base32 = b32encode(b16decode(item_hash.upper())).strip(b"=").lower().decode()
            func_url_1 = f"{settings.VM_URL_PATH.format(hash=item_hash)}"
            func_url_2 = f"{settings.VM_URL_HOST.format(hash_base32=hash_base32)}"
            console = Console()
            infos = [
                Text.from_markup("Your program is now [red]unpersistent[/red]. It implies a new item hash."),
                Text.from_markup(
                    f"\n\n[{prev_color}]- Prev persistent program: {item_hash} ➜ {prev_label}[/{prev_color}]\n[green]-"
                    f" New non-persistent program: {message.item_hash}[/green]."
                ),
                Text.assemble(
                    "\n\nAvailable on:\n",
                    Text.from_markup(
                        f"↳ [bright_yellow][link={func_url_1}]{func_url_1}[/link][/bright_yellow]\n",
                        style="italic",
                    ),
                    Text.from_markup(
                        f"↳ [dark_olive_green2][link={func_url_2}]{func_url_2}[/link][/dark_olive_green2]",
                        style="italic",
                    ),
                ),
            ]
            console.print(
                Panel(
                    Text.assemble(*infos),
                    title="Program: Unpersist",
                    border_style="orchid",
                    expand=False,
                    title_align="left",
                )
            )
        return message.item_hash


@app.command()
async def logs(
    item_hash: Annotated[str, typer.Argument(help="Item hash of program")],
    chain: Annotated[
        Optional[Chain], typer.Option(help=help_strings.PAYMENT_CHAIN_PROGRAM_USED, metavar=metavar_valid_chains)
    ] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    domain: Annotated[Optional[str], typer.Option(help=help_strings.PROMPT_PROGRAM_CRN_URL)] = None,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
):
    """Display the logs of a program

    Will only show logs from the selected CRN"""

    setup_logging(debug)

    account = _load_account(private_key, private_key_file, chain=chain)
    domain_ = sanitize_url(domain or Prompt.ask(help_strings.PROMPT_PROGRAM_CRN_URL))

    async with VmClient(account, domain_) as client:
        async with client.operate(vm_id=item_hash, operation="logs", method="GET") as response:
            logger.debug("Request %s %s", response.url, response.status)
            if response.status != 200:
                logger.debug(response)
                logger.debug(await response.text())

            if response.status == 404:
                echo("Server didn't found any execution of this program")
                return 1
            elif response.status == 403:
                echo("You are not the owner of this VM. Maybe try with another wallet?")
                return 1
            elif response.status != 200:
                echo(f"Server error: {response.status}. Please try again later")
                return 1
            echo("Received logs")
            log_entries = await response.json()
            for log in log_entries:
                echo(f'{log["__REALTIME_TIMESTAMP"]}>  {log["MESSAGE"]}')


@app.command()
async def runtime_checker(
    item_hash: Annotated[str, typer.Argument(help="Item hash of the runtime to check")],
    chain: Annotated[
        Optional[Chain], typer.Option(help=help_strings.ADDRESS_CHAIN, metavar=metavar_valid_chains)
    ] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    verbose: Annotated[bool, typer.Option(help="Display additional information")] = False,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
):
    """Check versions used by a runtime (distribution, python, nodejs, etc)"""

    setup_logging(debug)

    echo("Deploy runtime checker program...")
    try:
        program_hash = await upload(
            path=Path(__file__).resolve().parent / "program_utils/runtime_checker.squashfs",
            entrypoint="main:app",
            name="runtime_checker",
            runtime=item_hash,
            compute_units=1,
            vcpus=None,
            memory=None,
            timeout_seconds=None,
            internet=False,
            persistent=False,
            updatable=False,
            beta=False,
            skip_volume=True,
            skip_env_var=True,
            address=None,
            payment_chain=chain,
            channel=settings.DEFAULT_CHANNEL,
            private_key=private_key,
            private_key_file=private_key_file,
            print_messages=False,
            print_code_message=False,
            print_program_message=False,
            verbose=verbose,
            debug=debug,
        )
        if not program_hash:
            msg = "No program hash"
            raise Exception(msg)
    except Exception as e:
        echo("Failed to deploy the runtime checker program")
        raise typer.Exit(code=1) from e

    program_url = settings.VM_URL_PATH.format(hash=program_hash)
    versions: dict
    echo("Query runtime checker to retrieve versions...")
    try:
        timeout = aiohttp.ClientTimeout(total=settings.HTTP_REQUEST_TIMEOUT)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(program_url) as resp:
                resp.raise_for_status()
                versions = await resp.json()
    except Exception as e:
        logger.debug(f"Unexpected error when calling {program_url}: {e}")
        raise typer.Exit(code=1) from e

    echo("Delete runtime checker...")
    try:
        await delete(
            item_hash=program_hash,
            reason="Automatic deletion of the runtime checker program",
            keep_code=True,
            private_key=private_key,
            private_key_file=private_key_file,
            print_message=False,
            verbose=verbose,
            debug=debug,
        )
    except Exception as e:
        echo(f"Failed to delete the runtime checker program: {e}")
        raise typer.Exit(code=1) from e

    console = Console()
    infos = [Text.from_markup(f"[bold]Ref:[/bold] [bright_cyan]{item_hash}[/bright_cyan]")]
    for label, version in versions.items():
        color = "green" if bool(re.search(r"\d", version)) else "red"
        infos.append(Text.from_markup(f"\n[bold]{label}:[/bold] [{color}]{version}[/{color}]"))
    console.print(
        Panel(Text.assemble(*infos), title="Runtime Infos", border_style="violet", expand=False, title_align="left")
    )
