from __future__ import annotations

import inspect
import logging
from json import JSONDecodeError, dumps, loads
from pathlib import Path
from typing import Annotated, Optional

import typer
from aiohttp import ClientResponseError, ClientSession
from aleph.sdk.account import _load_account
from aleph.sdk.client import AuthenticatedAlephHttpClient
from aleph.sdk.conf import settings
from aleph.sdk.types import AccountFromPrivateKey
from aleph.sdk.utils import extended_json_encoder
from aleph_message.models import Chain, MessageType
from aleph_message.status import MessageStatus
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from aleph_client.commands import help_strings
from aleph_client.commands.utils import setup_logging
from aleph_client.utils import AsyncTyper, sanitize_url

logger = logging.getLogger(__name__)
app = AsyncTyper(no_args_is_help=True)


def is_same_context():
    caller = inspect.currentframe().f_back.f_back  # type: ignore
    current_file = __file__
    caller_file = caller.f_code.co_filename  # type: ignore
    return current_file == caller_file


@app.command()
async def forget(
    key: Annotated[str, typer.Argument(help="Aggregate key to remove")],
    subkeys: Annotated[
        Optional[str],
        typer.Option(
            help="Remove specified subkey(s) only. Must be a comma separated list. E.g. `key1` or `key1,key2`",
        ),
    ] = None,
    address: Annotated[Optional[str], typer.Option(help=help_strings.TARGET_ADDRESS)] = None,
    channel: Annotated[Optional[str], typer.Option(help=help_strings.CHANNEL)] = settings.DEFAULT_CHANNEL,
    inline: Annotated[bool, typer.Option(help="inline")] = False,
    sync: Annotated[bool, typer.Option(help="Sync response")] = False,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    print_message: bool = False,
    verbose: bool = True,
    debug: bool = False,
) -> bool:
    """Delete an aggregate by key or subkeys"""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)
    address = account.get_address() if address is None else address

    if key == "security" and not is_same_context():
        typer.echo(help_strings.AGGREGATE_SECURITY_KEY_PROTECTED)
        raise typer.Exit(1)

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        content = None
        if subkeys:
            content = {sk: None for sk in subkeys.split(",")}
        else:
            aggregates = await list_aggregates(
                address=address, private_key=private_key, private_key_file=private_key_file, verbose=False, debug=debug
            )
            if aggregates and key in aggregates.keys():
                content = {k: None for k in aggregates.get(key).keys()}
            else:
                typer.echo(f"Aggregate `{key}` not found")
                raise typer.Exit(1)

        message, status = await client.create_aggregate(
            key=key,
            content=content,
            channel=channel,
            sync=sync,
            inline=inline,
            address=address,
        )
        dumped_content = f"{message.model_dump_json(indent=4)}"

        if status != MessageStatus.REJECTED:
            if print_message:
                typer.echo(dumped_content)
            if verbose:
                label_subkeys = f" ➜ {subkeys}" if subkeys else ""
                typer.echo(f"Aggregate `{key}{label_subkeys}` has been deleted")
            return True
        elif verbose:
            typer.echo(f"Aggregate deletion has been rejected:\n{dumped_content}")
    return False


@app.command()
async def post(
    key: Annotated[str, typer.Argument(help="Aggregate key to create/update")],
    content: Annotated[
        str,
        typer.Argument(
            help=(
                'Aggregate content, in json format and between single quotes. E.g. \'{"a": 1, '
                '"b": 2}\'. If a subkey is provided, also allow to pass a string content between '
                "quotes"
            ),
        ),
    ],
    subkey: Annotated[Optional[str], typer.Option(help="Specified subkey where the content will be replaced")] = None,
    address: Annotated[Optional[str], typer.Option(help=help_strings.TARGET_ADDRESS)] = None,
    channel: Annotated[Optional[str], typer.Option(help=help_strings.CHANNEL)] = settings.DEFAULT_CHANNEL,
    inline: Annotated[bool, typer.Option(help="inline")] = False,
    sync: Annotated[bool, typer.Option(help="Sync response")] = False,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    print_message: bool = False,
    verbose: bool = True,
    debug: bool = False,
) -> bool:
    """Create or update an aggregate by key or subkey"""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)
    address = account.get_address() if address is None else address

    if key == "security" and not is_same_context():
        typer.echo(help_strings.AGGREGATE_SECURITY_KEY_PROTECTED)
        raise typer.Exit(1)

    content_dict: dict | str = content
    try:
        content_dict = loads(content)
    except JSONDecodeError as e:
        if not subkey:
            typer.echo("Invalid JSON for content. Please provide valid JSON")
            raise typer.Exit(1) from e

    if subkey:
        content_dict = {subkey: content_dict}

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        message, status = await client.create_aggregate(
            key=key,
            content=content_dict,
            channel=channel,
            sync=sync,
            inline=inline,
            address=address,
        )
        content = f"{message.model_dump_json(indent=4)}"

        if status != MessageStatus.REJECTED:
            if print_message:
                typer.echo(content)
            if verbose:
                label_subkey = f" ➜ {subkey}" if subkey else ""
                typer.echo(f"Aggregate `{key}{label_subkey}` has been created/updated")
            return True
        elif verbose:
            typer.echo(f"Aggregate creation/update has been rejected:\n{content}")
    return False


@app.command()
async def get(
    key: Annotated[str, typer.Argument(help="Aggregate key to fetch")],
    subkeys: Annotated[
        Optional[str],
        typer.Option(
            help="Fetch specified subkey(s) only. Must be a comma separated list. E.g. `key1` or `key1,key2`",
        ),
    ] = None,
    address: Annotated[Optional[str], typer.Option(help=help_strings.TARGET_ADDRESS)] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    verbose: bool = True,
    debug: bool = False,
) -> Optional[dict]:
    """Fetch an aggregate by key or subkeys"""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)
    address = account.get_address() if address is None else address

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        aggregates = None
        try:
            aggregates = await client.fetch_aggregate(address=address, key=key)
            if subkeys:
                aggregates = {k: v for k, v in aggregates.items() if k in subkeys.split(",")}
        except ClientResponseError:
            pass

        if verbose:
            if not aggregates:
                typer.echo("No aggregate found for the given key or subkeys")
            else:
                typer.echo(dumps(aggregates, indent=4, default=extended_json_encoder))

        return aggregates


@app.command(name="list")
async def list_aggregates(
    address: Annotated[Optional[str], typer.Option(help=help_strings.TARGET_ADDRESS)] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    json: Annotated[bool, typer.Option(help="Print as json instead of rich table")] = False,
    verbose: bool = True,
    debug: bool = False,
) -> Optional[dict]:
    """Display all aggregates associated to an account"""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)
    address = account.get_address() if address is None else address

    aggr_link = f"{sanitize_url(settings.API_HOST)}/api/v0/aggregates/{address}.json"
    async with ClientSession() as session:
        aggregates = None
        async with session.get(aggr_link) as resp:
            if resp.status == 200:
                aggregates = (await resp.json())["data"]

        if verbose:
            if not aggregates:
                typer.echo(f"Address: {address}\n\nNo aggregate data found\n")
            elif json:
                typer.echo(dumps(aggregates, indent=4, default=extended_json_encoder))
            else:
                infos = [
                    Text.from_markup(f"Address: [bright_cyan]{address}[/bright_cyan]\n\nKeys:"),
                ]
                for key, value in aggregates.items():
                    infos.append(
                        Text.from_markup(f"\n↳ [orange1]{key}[/orange1]:"),
                    )
                    if isinstance(value, dict) and any(v is None for _, v in value.items()):
                        infos.append(
                            Text.from_markup("\n[gray50]x empty[/gray50]"),
                        )
                    else:
                        for k, v in value.items():
                            infos.append(
                                Text.from_markup(
                                    f"\n• [orchid]{k}[/orchid]: {v if type(v) is str else dumps(v, indent=4)}"
                                ),
                            )
                console = Console()
                console.print(
                    Panel(
                        Text.assemble(*infos),
                        title="Aggregates",
                        border_style="bright_cyan",
                        expand=False,
                        title_align="left",
                    )
                )

        return aggregates


@app.command()
async def authorize(
    address: Annotated[str, typer.Argument(help=help_strings.TARGET_ADDRESS)],
    chain: Annotated[Optional[Chain], typer.Option(help="Only on specified chain")] = None,
    types: Annotated[
        Optional[str], typer.Option(help="Only for specified message types (comma separated list)")
    ] = None,
    channels: Annotated[Optional[str], typer.Option(help="Only on specified channels (comma separated list)")] = None,
    post_types: Annotated[
        Optional[str], typer.Option(help="Only for specified post types (comma separated list)")
    ] = None,
    aggregate_keys: Annotated[
        Optional[str], typer.Option(help="Only for specified aggregate keys (comma separated list)")
    ] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    print_message: bool = False,
    verbose: bool = True,
    debug: bool = False,
):
    """Grant specific publishing permissions to an address to act on behalf of this account"""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    data = await get(
        key="security",
        subkeys="authorizations",
        address=account.get_address(),
        private_key=private_key,
        private_key_file=private_key_file,
        verbose=False,
        debug=debug,
    )

    authorizations = None
    if data:
        authorizations = data.get("authorizations")
        new_auth: dict = {"address": address}
        if chain:
            new_auth["chain"] = chain.value
        if types:
            valid_types = []
            for t in types.split(","):
                try:
                    valid_types.append(MessageType(t.upper()).value)
                except ValueError as e:
                    logger.error(
                        f"Invalid value passed into `--types`: {t}\n"
                        f"Valid values: {', '.join([e.value for e in MessageType])}"
                    )
                    raise typer.Exit(1) from e
            new_auth["types"] = valid_types
        if channels:
            new_auth["channels"] = channels.split(",")
        if post_types:
            new_auth["post_types"] = post_types.split(",")
        if aggregate_keys:
            new_auth["aggregate_keys"] = aggregate_keys.split(",")
        authorizations.append(new_auth)
        if authorizations:
            success = await post(
                key="security",
                subkey="authorizations",
                content=dumps(authorizations),
                address=None,
                channel=settings.DEFAULT_CHANNEL,
                inline=True,
                sync=True,
                private_key=private_key,
                private_key_file=private_key_file,
                print_message=print_message,
                verbose=False,
                debug=debug,
            )
            if verbose:
                if success:
                    typer.echo(f"Permissions has been added for {address}")
                else:
                    typer.echo(f"Failed to add permissions for {address}")


@app.command()
async def revoke(
    address: Annotated[str, typer.Argument(help=help_strings.TARGET_ADDRESS)],
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    print_message: bool = False,
    verbose: bool = True,
    debug: bool = False,
):
    """Revoke all publishing permissions from an address acting on behalf of this account"""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    data = await get(
        key="security",
        subkeys="authorizations",
        address=account.get_address(),
        private_key=private_key,
        private_key_file=private_key_file,
        verbose=False,
        debug=debug,
    )

    authorizations = None
    if data:
        old_authorizations = data.get("authorizations")
        authorizations = [item for item in old_authorizations if item.get("address", "") != address]
        if old_authorizations != authorizations:
            success = await post(
                key="security",
                subkey="authorizations",
                content=dumps(authorizations),
                address=None,
                channel=settings.DEFAULT_CHANNEL,
                inline=True,
                sync=True,
                private_key=private_key,
                private_key_file=private_key_file,
                print_message=print_message,
                verbose=False,
                debug=debug,
            )
            if verbose:
                if success:
                    typer.echo(f"Permissions has been deleted for {address}")
                else:
                    typer.echo(f"Failed to delete permissions for {address}")
        elif verbose:
            typer.echo(f"No permission found for {address}. Ignored")


@app.command()
async def permissions(
    address: Annotated[Optional[str], typer.Option(help=help_strings.TARGET_ADDRESS)] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    json: Annotated[bool, typer.Option(help="Print as json instead of rich table")] = False,
    verbose: bool = True,
    debug: bool = False,
) -> Optional[dict]:
    """Display all permissions emitted by an account"""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)
    address = account.get_address() if address is None else address

    data = await get(
        key="security",
        subkeys="authorizations",
        address=address,
        private_key=private_key,
        private_key_file=private_key_file,
        verbose=False,
        debug=debug,
    )

    authorizations = None
    if data:
        authorizations = data.get("authorizations")
        if authorizations:
            if json:
                typer.echo(dumps(authorizations, indent=4, default=extended_json_encoder))
            elif verbose:
                infos = [
                    Text.from_markup(f"Address: [bright_cyan]{address}[/bright_cyan]\n\nAuthorizations by address:"),
                ]
                auth_addresses: dict = {}
                for auth in authorizations:
                    addr = auth["address"]
                    auth_address = auth_addresses[addr] = auth_addresses.get(addr, [])
                    keys = ["chain", "channels", "types", "post_types", "aggregate_keys"]
                    item = {key: auth.get(key) for key in keys if auth.get(key) is not None}
                    auth_address.append(item)
                for addr, allowances in auth_addresses.items():
                    infos.append(
                        Text.from_markup(f"\n↳ [orange1]{addr}[/orange1]"),
                    )
                    for item in allowances:
                        display_item = "[green]all[/green]"
                        if item:
                            display_item = ", ".join(
                                [
                                    "[orchid]{key}([white]"
                                    f"{value if isinstance(value, list) else ', '.join(value)}"
                                    "[/white])[/orchid]"
                                    for key, value in item.items()
                                ]
                            )
                        infos.append(Text.from_markup(f"\n• {display_item}"))

                console = Console()
                console.print(
                    Panel(
                        Text.assemble(*infos),
                        title="Permissions",
                        border_style="bright_cyan",
                        expand=False,
                        title_align="left",
                    )
                )
    if not authorizations and verbose:
        typer.echo(f"Address: {address}\n\nNo permission data found\n")

    return authorizations
