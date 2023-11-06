import json
from pathlib import Path
from typing import Optional, Mapping, Any

import typer
from aleph.sdk.account import _load_account
from aleph.sdk.client import AuthenticatedAlephClient
from aleph.sdk.conf import settings as sdk_settings
from aleph.sdk.types import AccountFromPrivateKey
from aleph_message.models import MessageType

from aleph_client.commands import help_strings
from aleph_client.commands.utils import setup_logging

from aleph_client.commands.utils import (
    colorful_message_json,
)


app = typer.Typer()


@app.command()
def forget(
    key: str = typer.Argument(..., help="Aggregate item hash to be removed."),
    reason: Optional[str] = typer.Option(
        None, help="A description of why the messages are being forgotten"
    ),
    channel: Optional[str] = typer.Option(default=None, help=help_strings.CHANNEL),
    private_key: Optional[str] = typer.Option(
        sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY
    ),
    private_key_file: Optional[Path] = typer.Option(
        sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE
    ),
    debug: bool = False,
):
    """Forget all the messages composing an aggregate."""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    with AuthenticatedAlephClient(
        account=account, api_server=sdk_settings.API_HOST
    ) as client:
        message_response = client.get_messages(
            addresses=[account.get_address()],
            message_type=MessageType.aggregate.value,
            content_keys=[key],
        )
        hash_list = [message["item_hash"] for message in message_response.messages]

        client.forget(hashes=hash_list, reason=reason, channel=channel)


@app.command()
def post(
    key: str = typer.Argument(..., help="Aggregate key to be created."),
    content: str = typer.Argument(
        ..., help="Aggregate content (ex : {'c': 3, 'd': 4})"
    ),
    address: Optional[str] = typer.Option(default=None, help="address"),
    channel: Optional[str] = typer.Option(default=None, help=help_strings.CHANNEL),
    inline: Optional[bool] = typer.Option(False, help="inline"),
    sync: Optional[bool] = typer.Option(False, help="Sync response"),
    private_key: Optional[str] = typer.Option(
        sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY
    ),
    private_key_file: Optional[Path] = typer.Option(
        sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE
    ),
    debug: bool = False,
):
    """Create an Aggregate"""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    try:
        content_dict = json.loads(content)
    except json.JSONDecodeError:
        typer.echo("Invalid JSON for content. Please provide valid JSON.")
        raise typer.Exit(1)

    with AuthenticatedAlephClient(
        account=account, api_server=sdk_settings.API_HOST
    ) as client:
        message, status = client.create_aggregate(
            key=key,
            content=content_dict,
            channel=channel,
            sync=sync,
            inline=inline,
            address=address,
        )
        log_message = json.dumps(message.dict(), indent=4)
        typer.echo(log_message)


@app.command()
def get(
    key: str = typer.Argument(..., help="Aggregate key to be fetched."),
    address: Optional[str] = typer.Option(default=None, help="Address"),
    limit: Optional[int] = typer.Option(default=100, help="limit of response"),
    private_key: Optional[str] = typer.Option(
        sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY
    ),
    private_key_file: Optional[Path] = typer.Option(
        sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE
    ),
    debug: bool = False,
):
    """Fetch an aggregate by key and content."""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)
    if account and not address:
        address = account.get_address()

    with AuthenticatedAlephClient(
        account=account, api_server=sdk_settings.API_HOST
    ) as client:
        aggregates = client.fetch_aggregate(address=address, key=key, limit=limit)

        if aggregates:
            typer.echo("Fetched aggregates:")
            for aggregate_key, aggregate_data in aggregates.items():
                typer.echo(f"Aggregate Key: {aggregate_key}")
                typer.echo(f"Aggregate Data: {json.dumps(aggregate_data, indent=4)}")
        else:
            typer.echo("No aggregates found for the given key and content.")


@app.command()
def amend(
    key: str = typer.Argument(..., help="Aggregate key to be ammend."),
    content: str = typer.Argument(
        ..., help="Aggregate content (ex : {'a': 1, 'b': 2})"
    ),
    address: Optional[str] = typer.Option(default=None, help="address"),
    channel: Optional[str] = typer.Option(default=None, help=help_strings.CHANNEL),
    inline: Optional[bool] = typer.Option(False, help="inline"),
    sync: Optional[bool] = typer.Option(False, help="Sync response"),
    private_key: Optional[str] = typer.Option(
        sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY
    ),
    private_key_file: Optional[Path] = typer.Option(
        sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE
    ),
    debug: bool = False,
):
    """Update an Aggregate"""

    setup_logging(debug)

    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    # if no address we load current account as a private key
    address = account.get_address() if address is None else address

    try:
        content_dict = json.loads(content)
    except json.JSONDecodeError:
        typer.echo("Invalid JSON for content. Please provide valid JSON.")
        raise typer.Exit(1)

    with AuthenticatedAlephClient(
        account=account, api_server=sdk_settings.API_HOST
    ) as client:
        # Fetch aggregates to check if the key is already present
        aggregates = client.fetch_aggregate(address=address, key=key, limit=100)

        if aggregates:
            message, status = client.create_aggregate(
                key=key,
                content=content_dict,
                channel=channel,
                sync=sync,
                inline=inline,
                address=address,
            )

            typer.echo(colorful_message_json(message))
        else:
            typer.echo("No aggregates found for the given key and content.")
