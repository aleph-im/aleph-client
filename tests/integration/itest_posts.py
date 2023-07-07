import pytest
from aleph_message.models import PostMessage
from aleph.sdk.exceptions import MessageNotFoundError
from tests.integration.toolkit import try_until
from .config import REFERENCE_NODE, TARGET_NODE
from aleph.sdk import AuthenticatedAlephClient
from aleph.sdk.conf import settings as sdk_settings
from aleph.sdk import AlephClient


async def get_message(item_hash: str):
    async with AlephClient(api_server=sdk_settings.API_HOST) as client:
        try:
            response = await client.get_message(item_hash, message_type=PostMessage)
            return response
        except MessageNotFoundError:
            return None


async def create_message_on_target(
    fixture_account, emitter_node: str, receiver_node: str
):
    """
    Create a POST message on the target node, then fetch it from the reference node.
    """
    data = {"content": "test"}
    async with AuthenticatedAlephClient(
        account=fixture_account, api_server=sdk_settings.API_HOST
    ) as client:
        message, status = await client.create_post(
            post_content=data,
            post_type="POST",
            ref=None,
            channel="INTEGRATION_TESTS",
            inline=True,
        )

    response = await try_until(
        get_message,
        lambda r: r is not None and r.content is not None,
        timeout=50,
        time_between_attempts=0.5,
        item_hash=message.item_hash,
    )
    assert status == 0
    assert response.content == message.content


@pytest.mark.asyncio
async def test_create_message_on_target(fixture_account):
    """
    Attempts to create a new message on the target node and verifies if the message can be fetched from
    the reference node.
    """
    await create_message_on_target(
        fixture_account, emitter_node=REFERENCE_NODE, receiver_node=TARGET_NODE
    )
