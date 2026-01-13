from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated, Optional

import typer
from aleph.sdk.client import AlephHttpClient, AuthenticatedAlephHttpClient
from aleph.sdk.conf import settings
from aleph_message.models import Chain, MessageType
from rich.console import Console
from rich.table import Table

from aleph_client.commands import help_strings
from aleph_client.commands.utils import setup_logging
from aleph_client.utils import AccountTypes, AsyncTyper, load_account

try:
    from aleph.sdk.types import AuthorizationBuilder
except ImportError:
    # Fallback to dict if SDK is not updated yet (though it should be)
    pass

logger = logging.getLogger(__name__)
app = AsyncTyper(no_args_is_help=True)


@app.command()
async def list(
    address: Annotated[Optional[str], typer.Option(help=help_strings.TARGET_ADDRESS)] = None,
    delegate: Annotated[Optional[str], typer.Option(help="Filter by delegated address")] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    chain: Annotated[Optional[Chain], typer.Option(help=help_strings.ADDRESS_CHAIN)] = None,
    debug: bool = False,
):
    """List authorizations for an address"""
    setup_logging(debug)

    if address is None:
        account: AccountTypes = load_account(
            private_key_str=private_key, private_key_file=private_key_file, chain=chain
        )
        address = account.get_address()

    async with AlephHttpClient(api_server=settings.API_HOST) as client:
        # get_authorizations is expected to be in the updated SDK (see sdk.diff)
        authorizations = await client.get_authorizations(address)

    if delegate:
        authorizations = [auth for auth in authorizations if auth.address == delegate]

    console = Console()
    table = Table(title=f"Authorizations for {address}")
    table.add_column("Delegate", style="cyan")
    table.add_column("Chain", style="magenta")
    table.add_column("Channels", style="green")
    table.add_column("Message Types", style="blue")
    table.add_column("Post Types", style="yellow")
    table.add_column("Aggregate Keys", style="red")

    for auth in authorizations:
        table.add_row(
            auth.address,
            str(auth.chain or ""),
            ", ".join(auth.channels or []),
            ", ".join([t.value for t in auth.types] if auth.types else []),
            ", ".join(auth.post_types or []),
            ", ".join(auth.aggregate_keys or []),
        )

    console.print(table)


@app.command()
async def add(
    delegate_address: Annotated[str, typer.Argument(help="Address to delegate to")],
    chain: Annotated[Optional[Chain], typer.Option(help="Only on specified chain")] = None,
    channels: Annotated[Optional[str], typer.Option(help="Comma separated list of channels")] = None,
    message_types: Annotated[Optional[str], typer.Option(help="Comma separated list of message types")] = None,
    post_types: Annotated[Optional[str], typer.Option(help="Comma separated list of post types")] = None,
    aggregate_keys: Annotated[Optional[str], typer.Option(help="Comma separated list of aggregate keys")] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    debug: bool = False,
):
    """Add a permission for a specific address"""
    setup_logging(debug)
    account: AccountTypes = load_account(private_key_str=private_key, private_key_file=private_key_file, chain=chain)

    builder = AuthorizationBuilder(address=delegate_address)
    if chain:
        builder.chain(chain)
    if channels:
        for channel in channels.split(","):
            builder.channel(channel.strip())
    if message_types:
        for t in message_types.split(","):
            builder.message_type(MessageType(t.strip().upper()))
    if post_types:
        for pt in post_types.split(","):
            builder.post_type(pt.strip())
    if aggregate_keys:
        for ak in aggregate_keys.split(","):
            builder.aggregate_key(ak.strip())

    authorization = builder.build()

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        await client.add_authorization(authorization)

    typer.echo(f"Added authorization for {delegate_address}")


@app.command()
async def revoke(
    delegate_address: Annotated[Optional[str], typer.Argument(help="Address to revoke permissions from")] = None,
    all: Annotated[bool, typer.Option("--all", help="Revoke all permissions")] = False,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    chain: Annotated[Optional[Chain], typer.Option(help=help_strings.ADDRESS_CHAIN)] = None,
    debug: bool = False,
):
    """Revoke permissions for an address"""
    setup_logging(debug)

    if not all and not delegate_address:
        typer.echo("Error: Please provide a delegate address or use --all")
        raise typer.Exit(1)

    account: AccountTypes = load_account(private_key_str=private_key, private_key_file=private_key_file, chain=chain)

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        if all:
            await client.update_all_authorizations([])
            typer.echo("Revoked all authorizations")
        else:
            await client.revoke_all_authorizations(delegate_address)
            typer.echo(f"Revoked authorizations for {delegate_address}")
