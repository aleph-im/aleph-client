import pytest
from aleph_message import Message
from aleph_message.models import MessagesResponse

from tests.integration.toolkit import try_until

from .config import REFERENCE_NODE, TARGET_NODE


async def create_message_on_target(
    fixture_account, emitter_node: str, receiver_node: str
):
    """
    Create a POST message on the target node, then fetch it from the reference node.
    """

    post_message, message_status = await create_post(
        account=fixture_account,
        post_content=None,
        post_type="POST",
        channel="INTEGRATION_TESTS",
        session=None,
        api_server=emitter_node,
    )

    def response_contains_messages(response: MessagesResponse) -> bool:
        return len(response.messages) > 0

    # create_message = Message(**created_message_dict)
    response_dict = await try_until(
        get_messages,
        response_contains_messages,
        timeout=5,
        hashes=[post_message.item_hash],
        api_server=receiver_node,
    )

    message_from_target = Message(**response_dict["messages"][0])
    assert post_message.item_hash == message_from_target.item_hash


@pytest.mark.asyncio
async def test_create_message_on_target(fixture_account):
    """
    Attempts to create a new message on the target node and verifies if the message can be fetched from
    the reference node.
    """
    await create_message_on_target(
        fixture_account, emitter_node=TARGET_NODE, receiver_node=REFERENCE_NODE
    )


@pytest.mark.asyncio
async def test_create_message_on_reference(fixture_account):
    """
    Attempts to create a new message on the reference node and verifies if the message can be fetched from
    the target node.
    """
    await create_message_on_target(
        fixture_account, emitter_node=REFERENCE_NODE, receiver_node=TARGET_NODE
    )
