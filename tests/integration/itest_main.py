import asyncio

import pytest

from aleph_message import Message, MessagesResponse
from aleph_client.asynchronous import create_post, get_messages, create_aggregate, fetch_aggregate
from aleph_client.types import Account

TARGET_NODE = "http://163.172.70.92:4024"
REFERENCE_NODE = "https://api2.aleph.im"


async def post_message_and_check(fixture_account: Account, target_node: str, reference_node: str):
    created_message_dict = await create_post(
        account=fixture_account,
        post_content=None,
        post_type="POST",
        channel="INTEGRATION_TESTS",
        session=None,
        api_server=target_node,
    )

    # create_message = Message(**created_message_dict)

    for trial in range(10):
        response_dict = await get_messages(
            hashes=[created_message_dict["item_hash"]],
            api_server=reference_node,
        )

        if response_dict["messages"]:
            break
        else:
            await asyncio.sleep(0.5)
    else:
        raise TimeoutError("No response within 10 trials")

    print(response_dict["messages"][0])
    message_from_target = Message(**response_dict["messages"][0])
    assert created_message_dict["item_hash"] == message_from_target.item_hash


async def create_message_on_target(fixture_account, emitter_node: str, receiver_node: str):
    """
    Create a POST message on the target node, then fetch it from the reference node.
    """


    created_message_dict = await create_post(
        account=fixture_account,
        post_content=None,
        post_type="POST",
        channel="INTEGRATION_TESTS",
        session=None,
        api_server=emitter_node,
    )

    # create_message = Message(**created_message_dict)

    for trial in range(10):
        response_dict = await asyncio.wait_for(get_messages(
            hashes=[created_message_dict["item_hash"]],
            api_server=receiver_node,
        ), timeout=2)

        if response_dict["messages"]:
            break
        else:
            await asyncio.sleep(0.5)
    else:
        raise TimeoutError("No response within 10 trials")

    message_from_target = Message(**response_dict["messages"][0])
    assert created_message_dict["item_hash"] == message_from_target.item_hash


@pytest.mark.asyncio
async def test_create_message(fixture_account):
    # From target to reference:
    await create_message_on_target(fixture_account, emitter_node=TARGET_NODE, receiver_node=REFERENCE_NODE)
    # From reference to target:
    await create_message_on_target(fixture_account, emitter_node=REFERENCE_NODE, receiver_node=TARGET_NODE)



async def test_create_aggregate(fixture_account):
    await create_aggregate(

    )