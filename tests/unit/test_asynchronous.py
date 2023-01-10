from unittest.mock import MagicMock, patch, AsyncMock

import pytest as pytest
from aleph_message.models import (
    PostMessage,
    AggregateMessage,
    StoreMessage,
    ProgramMessage,
    ForgetMessage,
)

from aleph_client.types import StorageEnum, MessageStatus

from aleph_client.asynchronous import (
    create_post,
    _get_fallback_session,
    create_aggregate,
    create_store,
    create_program,
    forget,
)


def new_mock_session_with_post_success():
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.json.return_value = {
        "message_status": "processed",
        "publication_status": {"status": "success", "failed": []},
    }

    mock_post = AsyncMock()
    mock_post.return_value = mock_response

    mock_session = MagicMock()
    mock_session.post.return_value.__aenter__ = mock_post
    return mock_session


@pytest.mark.asyncio
async def test_create_post(ethereum_account):
    _get_fallback_session.cache_clear()

    content = {"Hello": "World"}

    mock_session = new_mock_session_with_post_success()

    post_message, message_status = await create_post(
        account=ethereum_account,
        post_content=content,
        post_type="TEST",
        channel="TEST",
        session=mock_session,
        api_server="https://example.org",
        sync=True,
    )

    assert mock_session.post.called
    assert isinstance(post_message, PostMessage)
    assert message_status == MessageStatus.PROCESSED


@pytest.mark.asyncio
async def test_create_aggregate(ethereum_account):
    _get_fallback_session.cache_clear()

    content = {"Hello": "World"}

    mock_session = new_mock_session_with_post_success()

    _ = await create_aggregate(
        account=ethereum_account,
        key="hello",
        content=content,
        channel="TEST",
        session=mock_session,
    )

    aggregate_message, message_status = await create_aggregate(
        account=ethereum_account,
        key="hello",
        content="world",
        channel="TEST",
        session=mock_session,
        api_server="https://example.org",
    )

    assert mock_session.post.called
    assert isinstance(aggregate_message, AggregateMessage)


@pytest.mark.asyncio
async def test_create_store(ethereum_account):
    _get_fallback_session.cache_clear()

    mock_session = new_mock_session_with_post_success()

    mock_ipfs_push_file = AsyncMock()
    mock_ipfs_push_file.return_value = "QmRTV3h1jLcACW4FRfdisokkQAk4E4qDhUzGpgdrd4JAFy"

    with patch("aleph_client.asynchronous.ipfs_push_file", mock_ipfs_push_file):
        _ = await create_store(
            account=ethereum_account,
            file_content=b"HELLO",
            channel="TEST",
            storage_engine=StorageEnum.ipfs,
            session=mock_session,
            api_server="https://example.org",
        )

        _ = await create_store(
            account=ethereum_account,
            file_hash="QmRTV3h1jLcACW4FRfdisokkQAk4E4qDhUzGpgdrd4JAFy",
            channel="TEST",
            storage_engine=StorageEnum.ipfs,
            session=mock_session,
            api_server="https://example.org",
        )

    mock_storage_push_file = AsyncMock()
    mock_storage_push_file.return_value = (
        "QmRTV3h1jLcACW4FRfdisokkQAk4E4qDhUzGpgdrd4JAFy"
    )

    with patch("aleph_client.asynchronous.storage_push_file", mock_storage_push_file):

        store_message, message_status = await create_store(
            account=ethereum_account,
            file_content=b"HELLO",
            channel="TEST",
            storage_engine=StorageEnum.storage,
            session=mock_session,
            api_server="https://example.org",
        )

    assert mock_session.post.called
    assert isinstance(store_message, StoreMessage)


@pytest.mark.asyncio
async def test_create_program(ethereum_account):
    _get_fallback_session.cache_clear()

    mock_session = new_mock_session_with_post_success()

    program_message, message_status = await create_program(
        account=ethereum_account,
        program_ref="FAKE-HASH",
        entrypoint="main:app",
        runtime="FAKE-HASH",
        channel="TEST",
        session=mock_session,
        api_server="https://example.org",
    )

    assert mock_session.post.called
    assert isinstance(program_message, ProgramMessage)


@pytest.mark.asyncio
async def test_forget(ethereum_account):
    _get_fallback_session.cache_clear()

    mock_session = new_mock_session_with_post_success()

    forget_message, message_status = await forget(
        account=ethereum_account,
        hashes=["QmRTV3h1jLcACW4FRfdisokkQAk4E4qDhUzGpgdrd4JAFy"],
        reason="GDPR",
        channel="TEST",
        session=mock_session,
        api_server="https://example.org",
    )

    assert mock_session.post.called
    assert isinstance(forget_message, ForgetMessage)
