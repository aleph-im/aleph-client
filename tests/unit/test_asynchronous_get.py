import pytest
from aleph_message.models import MessageType, MessagesResponse

from aleph_client.asynchronous import (
    get_messages,
    fetch_aggregates,
    fetch_aggregate,
    _get_fallback_session,
)


@pytest.mark.asyncio
async def test_fetch_aggregate():
    _get_fallback_session.cache_clear()

    response = await fetch_aggregate(
        address="0xa1B3bb7d2332383D96b7796B908fB7f7F3c2Be10", key="corechannel"
    )
    assert response.keys() == {"nodes", "resource_nodes"}


@pytest.mark.asyncio
async def test_fetch_aggregates():
    _get_fallback_session.cache_clear()

    response = await fetch_aggregates(
        address="0xa1B3bb7d2332383D96b7796B908fB7f7F3c2Be10"
    )
    assert response.keys() == {"corechannel"}
    assert response["corechannel"].keys() == {"nodes", "resource_nodes"}


@pytest.mark.asyncio
async def test_get_posts():
    _get_fallback_session.cache_clear()

    response: MessagesResponse = await get_messages(
        pagination=2,
        message_type=MessageType.post,
    )

    messages = response.messages
    assert len(messages) > 1
    for message in messages:
        assert message.type == MessageType.post


@pytest.mark.asyncio
async def test_get_messages():
    _get_fallback_session.cache_clear()

    response: MessagesResponse = await get_messages(
        pagination=2,
    )

    messages = response.messages
    assert len(messages) > 1
    assert messages[0].type
    assert messages[0].sender
