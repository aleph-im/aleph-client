from typing import Callable, Dict

import pytest

from aleph_client.asynchronous import create_post, get_posts, get_messages, forget
from aleph_client.types import Account
from aleph_client.user_session import UserSession
from .config import REFERENCE_NODE, TARGET_NODE, TEST_CHANNEL
from .toolkit import try_until


async def create_and_forget_post(
    account: Account, emitter_node: str, receiver_node: str, channel=TEST_CHANNEL
) -> str:
    async def wait_matching_posts(
        item_hash: str,
        condition: Callable[[Dict], bool],
        timeout: int = 5,
    ):
        async with UserSession(account=account, api_server=receiver_node) as rx_session:
            return await try_until(
                get_posts,
                condition,
                session=rx_session,
                timeout=timeout,
                hashes=[item_hash],
            )

    async with UserSession(account=account, api_server=emitter_node) as tx_session:
        post_message, message_status = await create_post(
            session=tx_session,
            post_content="A considerate and politically correct post.",
            post_type="POST",
            channel="INTEGRATION_TESTS",
        )

    # Wait for the message to appear on the receiver. We don't check the values,
    # they're checked in other integration tests.
    get_post_response = await wait_matching_posts(
        post_message.item_hash,
        lambda response: len(response["posts"]) > 0,
    )
    print(get_post_response)

    post_hash = post_message.item_hash
    reason = "This well thought-out content offends me!"
    async with UserSession(account=account, api_server=emitter_node) as tx_session:
        forget_message, forget_status = await forget(
            session=tx_session,
            hashes=[post_hash],
            reason=reason,
            channel=channel,
        )

    assert forget_message.sender == account.get_address()
    assert forget_message.content.reason == reason
    assert forget_message.content.hashes == [post_hash]

    print(forget_message)

    # Wait until the message is forgotten
    forgotten_posts = await wait_matching_posts(
        post_hash,
        lambda response: "forgotten_by" in response["posts"][0],
        timeout=15,
    )

    assert len(forgotten_posts["posts"]) == 1
    forgotten_post = forgotten_posts["posts"][0]
    assert forgotten_post["forgotten_by"] == [forget_message.item_hash]
    assert forgotten_post["item_content"] is None
    print(forgotten_post)

    return post_hash


@pytest.mark.asyncio
async def test_create_and_forget_post_on_target(fixture_account):
    """
    Create a post on the target node, then forget it and check that the change is propagated
    to the reference node.
    """
    _ = await create_and_forget_post(fixture_account, TARGET_NODE, REFERENCE_NODE)


@pytest.mark.asyncio
async def test_create_and_forget_post_on_reference(fixture_account):
    """
    Create a post on the reference node, then forget it and check that the change is propagated
    to the target node.
    """
    _ = await create_and_forget_post(fixture_account, REFERENCE_NODE, TARGET_NODE)


@pytest.mark.asyncio
async def test_forget_a_forget_message(fixture_account):
    """
    Attempts to forget a forget message. This should fail.
    """

    # TODO: this test should be moved to the PyAleph API tests, once a framework is in place.
    post_hash = await create_and_forget_post(fixture_account, TARGET_NODE, TARGET_NODE)
    async with UserSession(account=fixture_account, api_server=TARGET_NODE) as session:
        get_post_response = await get_posts(session=session, hashes=[post_hash])
        assert len(get_post_response["posts"]) == 1
        post = get_post_response["posts"][0]

        forget_message_hash = post["forgotten_by"][0]
        forget_message, forget_status = await forget(
            session=session,
            hashes=[forget_message_hash],
            reason="I want to remember this post. Maybe I can forget I forgot it?",
            channel=TEST_CHANNEL,
        )

        print(forget_message)

        get_forget_message_response = await get_messages(
            session=session,
            hashes=[forget_message_hash],
            channels=[TEST_CHANNEL],
        )
        assert len(get_forget_message_response.messages) == 1
        forget_message = get_forget_message_response.messages[0]
        print(forget_message)

        assert "forgotten_by" not in forget_message
