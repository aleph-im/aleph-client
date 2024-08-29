from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from aleph.sdk.account import _load_account
from aleph.sdk.client import AuthenticatedAlephHttpClient
from aleph.sdk.conf import settings
from aleph.sdk.query.filters import MessageFilter
from aleph.sdk.types import AccountFromPrivateKey
from aleph.sdk.utils import extended_json_encoder
from aleph_message.models.base import MessageType

from aleph_client.commands import help_strings
from aleph_client.commands.utils import setup_logging
from aleph_client.utils import AsyncTyper

app = AsyncTyper(no_args_is_help=True)


@app.command()
async def forget(
    key: str = typer.Argument(..., help="Aggregate item hash to be removed."),
    reason: Optional[str] = typer.Option(None, help="A description of why the messages are being forgotten"),
    channel: Optional[str] = typer.Option(default=settings.DEFAULT_CHANNEL, help=help_strings.CHANNEL),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    """Forget all the messages composing an aggregate."""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        message_response = await client.get_messages(
            message_filter=MessageFilter(
                addresses=[account.get_address()],
                message_types=[MessageType.aggregate],
                content_keys=[key],
            )
        )
        hash_list = [message.item_hash for message in message_response.messages]

        await client.forget(hashes=hash_list, reason=reason, channel=channel)


@app.command()
async def post(
    key: str = typer.Argument(..., help="Aggregate key to be created."),
    content: str = typer.Argument(..., help="Aggregate content (ex : {'c': 3, 'd': 4})"),
    address: Optional[str] = typer.Option(default=None, help="address"),
    channel: Optional[str] = typer.Option(default=settings.DEFAULT_CHANNEL, help=help_strings.CHANNEL),
    inline: bool = typer.Option(False, help="inline"),
    sync: bool = typer.Option(False, help="Sync response"),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    """Create or Update aggregate"""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    try:
        content_dict = json.loads(content)
    except json.JSONDecodeError:
        typer.echo("Invalid JSON for content. Please provide valid JSON.")
        raise typer.Exit(1)

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        message, _ = await client.create_aggregate(
            key=key,
            content=content_dict,
            channel=channel,
            sync=sync,
            inline=inline,
            address=address,
        )
        log_message = json.dumps(message.dict(), indent=4, default=extended_json_encoder)
        typer.echo(log_message)


@app.command()
async def get(
    key: str = typer.Argument(..., help="Aggregate key to be fetched."),
    address: Optional[str] = typer.Option(default=None, help="Address"),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    debug: bool = False,
):
    """Fetch an aggregate by key and content."""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    # if no address we load current account as a private key
    address = account.get_address() if address is None else address

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
        aggregates = await client.fetch_aggregate(address=address, key=key)

        if aggregates:
            typer.echo(json.dumps(aggregates, indent=4, default=extended_json_encoder))
        else:
            typer.echo("No aggregates found for the given key and content.")
