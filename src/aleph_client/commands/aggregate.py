from pathlib import Path
from typing import Optional

import typer
from aleph.sdk.account import _load_account
from aleph.sdk.client import AuthenticatedAlephHttpClient
from aleph.sdk.conf import settings as sdk_settings
from aleph.sdk.types import AccountFromPrivateKey
from aleph.sdk.query.filters import MessageFilter
from aleph_message.models import MessageType

from aleph_client.commands import help_strings
from aleph_client.commands.utils import setup_logging
from aleph_client.utils import AsyncTyper

app = AsyncTyper()


@app.command()
async def forget(
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

    async with AuthenticatedAlephHttpClient(
        account=account, api_server=sdk_settings.API_HOST
    ) as client:
        message_response = await client.get_messages(
            message_filter=MessageFilter(
                addresses=[account.get_address()],
                message_types=[MessageType.aggregate.value],
                content_keys=[key],
            )
        )
        hash_list = [message["item_hash"] for message in message_response.messages]

        await client.forget(hashes=hash_list, reason=reason, channel=channel)
