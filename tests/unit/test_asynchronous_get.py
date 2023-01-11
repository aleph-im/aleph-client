import unittest
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import MessageType, MessagesResponse

from aleph_client.asynchronous import (
    get_messages,
    fetch_aggregates,
    fetch_aggregate,
)
from aleph_client.conf import settings
from aleph_client.types import Account
from aleph_client.user_session import UserSession


def make_mock_session(mock_account: Account, get_return_value: Dict[str, Any]):

    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.json = AsyncMock(side_effect=lambda: get_return_value)

    mock_get = AsyncMock()
    mock_get.return_value = mock_response

    mock_session = MagicMock()
    mock_session.get.return_value.__aenter__ = mock_get

    user_session = AsyncMock()
    user_session.http_session = mock_session
    user_session.account = mock_account

    return user_session


@pytest.mark.asyncio
async def test_fetch_aggregate(ethereum_account: Account):
    mock_session = make_mock_session(
        ethereum_account, {"data": {"corechannel": {"nodes": [], "resource_nodes": []}}}
    )

    response = await fetch_aggregate(
        session=mock_session,
        address="0xa1B3bb7d2332383D96b7796B908fB7f7F3c2Be10",
        key="corechannel",
    )
    assert response.keys() == {"nodes", "resource_nodes"}


@pytest.mark.asyncio
async def test_fetch_aggregates(ethereum_account: Account):
    mock_session = make_mock_session(
        ethereum_account, {"data": {"corechannel": {"nodes": [], "resource_nodes": []}}}
    )

    response = await fetch_aggregates(
        session=mock_session, address="0xa1B3bb7d2332383D96b7796B908fB7f7F3c2Be10"
    )
    assert response.keys() == {"corechannel"}
    assert response["corechannel"].keys() == {"nodes", "resource_nodes"}


@pytest.mark.asyncio
async def test_get_posts(ethereum_account: Account):
    async with UserSession(
        account=ethereum_account, api_server=settings.API_HOST
    ) as session:
        response: MessagesResponse = await get_messages(
            session=session,
            pagination=2,
            message_type=MessageType.post,
        )

        messages = response.messages
        assert len(messages) > 1
        for message in messages:
            assert message.type == MessageType.post


@pytest.mark.asyncio
async def test_get_messages(ethereum_account: Account):
    async with UserSession(
        account=ethereum_account, api_server=settings.API_HOST
    ) as session:
        response: MessagesResponse = await get_messages(
            session=session,
            pagination=2,
        )

        messages = response.messages
        assert len(messages) > 1
        assert messages[0].type
        assert messages[0].sender


if __name__ == "__main __":
    unittest.main()
