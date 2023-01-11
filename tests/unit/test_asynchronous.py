from unittest.mock import patch, AsyncMock

import pytest as pytest
from aleph_message.models import (
    PostMessage,
    AggregateMessage,
    StoreMessage,
    ProgramMessage,
    ForgetMessage,
)

from aleph_client.asynchronous import (
    create_post,
    create_aggregate,
    create_store,
    create_program,
    forget,
)
from aleph_client.types import StorageEnum, MessageStatus, Account


@pytest.fixture
def mock_session_with_post_success(mocker, ethereum_account: Account):
    mock_response = mocker.AsyncMock()
    mock_response.status = 202
    mock_response.json.return_value = {
        "message_status": "pending",
        "publication_status": {"status": "success", "failed": []},
    }

    mock_post = mocker.AsyncMock()
    mock_post.return_value = mock_response

    mock_session = mocker.MagicMock()
    mock_session.post.return_value.__aenter__ = mock_post

    user_session = mocker.AsyncMock()
    user_session.http_session = mock_session
    user_session.account = ethereum_account

    return user_session


@pytest.mark.asyncio
async def test_create_post(mock_session_with_post_success):

    mock_session = mock_session_with_post_success
    content = {"Hello": "World"}

    post_message, message_status = await create_post(
        session=mock_session,
        post_content=content,
        post_type="TEST",
        channel="TEST",
    )

    assert mock_session.http_session.post.called
    assert isinstance(post_message, PostMessage)
    assert message_status == MessageStatus.PENDING


@pytest.mark.asyncio
async def test_create_aggregate(mock_session_with_post_success):

    mock_session = mock_session_with_post_success

    aggregate_message, message_status = await create_aggregate(
        session=mock_session,
        key="hello",
        content={"Hello": "world"},
        channel="TEST",
    )

    assert mock_session.http_session.post.called
    assert isinstance(aggregate_message, AggregateMessage)


@pytest.mark.asyncio
async def test_create_store(mock_session_with_post_success):

    mock_session = mock_session_with_post_success

    mock_ipfs_push_file = AsyncMock()
    mock_ipfs_push_file.return_value = "QmRTV3h1jLcACW4FRfdisokkQAk4E4qDhUzGpgdrd4JAFy"

    with patch("aleph_client.asynchronous.ipfs_push_file", mock_ipfs_push_file):
        _ = await create_store(
            session=mock_session,
            file_content=b"HELLO",
            channel="TEST",
            storage_engine=StorageEnum.ipfs,
        )

        _ = await create_store(
            session=mock_session,
            file_hash="QmRTV3h1jLcACW4FRfdisokkQAk4E4qDhUzGpgdrd4JAFy",
            channel="TEST",
            storage_engine=StorageEnum.ipfs,
        )

    mock_storage_push_file = AsyncMock()
    mock_storage_push_file.return_value = (
        "QmRTV3h1jLcACW4FRfdisokkQAk4E4qDhUzGpgdrd4JAFy"
    )

    with patch("aleph_client.asynchronous.storage_push_file", mock_storage_push_file):
        store_message, message_status = await create_store(
            session=mock_session,
            file_content=b"HELLO",
            channel="TEST",
            storage_engine=StorageEnum.storage,
        )

    assert mock_session.http_session.post.called
    assert isinstance(store_message, StoreMessage)


@pytest.mark.asyncio
async def test_create_program(mock_session_with_post_success):

    mock_session = mock_session_with_post_success

    program_message, message_status = await create_program(
        session=mock_session,
        program_ref="FAKE-HASH",
        entrypoint="main:app",
        runtime="FAKE-HASH",
        channel="TEST",
    )

    assert mock_session.http_session.post.called
    assert isinstance(program_message, ProgramMessage)


@pytest.mark.asyncio
async def test_forget(mock_session_with_post_success):

    mock_session = mock_session_with_post_success

    forget_message, message_status = await forget(
        session=mock_session,
        hashes=["QmRTV3h1jLcACW4FRfdisokkQAk4E4qDhUzGpgdrd4JAFy"],
        reason="GDPR",
        channel="TEST",
    )

    assert mock_session.http_session.post.called
    assert isinstance(forget_message, ForgetMessage)
