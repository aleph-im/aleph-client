import os
import time 
from unittest.mock import MagicMock, patch, AsyncMock

import pytest as pytest
from aleph_message.models import (
    PostMessage,
    AggregateMessage,
    StoreMessage,
    ProgramMessage,
    ForgetMessage,
    PostContent, 
    MessageType, 
    AlephMessage
)

from aleph_client.conf import settings
from aleph_client.types import StorageEnum

from aleph_client.asynchronous import (
    create_post,
    _get_fallback_session,
    create_aggregate,
    create_store,
    create_program,
    forget,
    submit
)
from aleph_client.chains.common import get_fallback_private_key
from aleph_client.chains.ethereum import ETHAccount
from build.lib.aleph_client.__main__ import post
from build.lib.aleph_client.asynchronous import fetch_aggregates


def new_mock_session_with_post_success():
    mock_response = AsyncMock()
    mock_response.json.return_value = {"status": "success"}

    mock_post = AsyncMock()
    mock_post.return_value = mock_response

    mock_session = MagicMock()
    mock_session.post.return_value.__aenter__ = mock_post
    return mock_session


def new_mock_session_with_post_success():
    mock_response = AsyncMock()
    mock_response.json.return_value = {"status": "success"}

    mock_post = AsyncMock()
    mock_post.return_value = mock_response

    mock_session = MagicMock()
    mock_session.post.return_value.__aenter__ = mock_post
    return mock_session


@pytest.mark.asyncio
async def test_create_post():
    _get_fallback_session.cache_clear()

    if os.path.exists(settings.PRIVATE_KEY_FILE):
        os.remove(settings.PRIVATE_KEY_FILE)

    private_key = get_fallback_private_key()
    account: ETHAccount = ETHAccount(private_key=private_key)

    content = {"Hello": "World"}

    mock_session = new_mock_session_with_post_success()

    new_post = await create_post(
        account=account,
        post_content=content,
        post_type="TEST",
        channel="TEST",
        session=mock_session,
        api_server="https://example.org",
    )

    assert mock_session.post.called
    assert isinstance(new_post, PostMessage)


@pytest.mark.asyncio
async def test_create_aggregate():
    _get_fallback_session.cache_clear()

    if os.path.exists(settings.PRIVATE_KEY_FILE):
        os.remove(settings.PRIVATE_KEY_FILE)

    private_key = get_fallback_private_key()
    account: ETHAccount = ETHAccount(private_key=private_key)

    content = {"Hello": "World"}

    mock_session = new_mock_session_with_post_success()

    await create_aggregate(
        account=account,
        key="hello",
        content=content,
        channel="TEST",
        session=mock_session,
    )

    new_post = await create_aggregate(
        account=account,
        key="hello",
        content="world",
        channel="TEST",
        session=mock_session,
        api_server="https://example.org",
    )

    assert mock_session.post.called
    assert isinstance(new_post, AggregateMessage)


@pytest.mark.asyncio
async def test_create_store():
    _get_fallback_session.cache_clear()

    if os.path.exists(settings.PRIVATE_KEY_FILE):
        os.remove(settings.PRIVATE_KEY_FILE)

    private_key = get_fallback_private_key()
    account: ETHAccount = ETHAccount(private_key=private_key)

    mock_session = new_mock_session_with_post_success()

    mock_ipfs_push_file = AsyncMock()
    mock_ipfs_push_file.return_value = "FAKE-HASH"

    with patch("aleph_client.asynchronous.ipfs_push_file", mock_ipfs_push_file):

        await create_store(
            account=account,
            file_content=b"HELLO",
            # file_hash="abcde",
            channel="TEST",
            storage_engine=StorageEnum.ipfs,
            session=mock_session,
            api_server="https://example.org",
        )

        await create_store(
            account=account,
            # file_content=b"HELLO",
            file_hash="FAKE-HASH",
            channel="TEST",
            storage_engine=StorageEnum.ipfs,
            session=mock_session,
            api_server="https://example.org",
        )

    mock_storage_push_file = AsyncMock()
    mock_storage_push_file.return_value = "FAKE-HASH"

    with patch("aleph_client.asynchronous.storage_push_file", mock_storage_push_file):

        new_post = await create_store(
            account=account,
            file_content=b"HELLO",
            channel="TEST",
            storage_engine=StorageEnum.storage,
            session=mock_session,
            api_server="https://example.org",
        )

    assert mock_session.post.called
    assert isinstance(new_post, StoreMessage)


@pytest.mark.asyncio
async def test_create_program():
    _get_fallback_session.cache_clear()

    if os.path.exists(settings.PRIVATE_KEY_FILE):
        os.remove(settings.PRIVATE_KEY_FILE)

    private_key = get_fallback_private_key()
    account: ETHAccount = ETHAccount(private_key=private_key)

    mock_session = new_mock_session_with_post_success()

    new_post = await create_program(
        account=account,
        program_ref="FAKE-HASH",
        entrypoint="main:app",
        runtime="FAKE-HASH",
        channel="TEST",
        session=mock_session,
        api_server="https://example.org",
    )

    assert mock_session.post.called
    assert isinstance(new_post, ProgramMessage)


@pytest.mark.asyncio
async def test_forget():
    _get_fallback_session.cache_clear()

    if os.path.exists(settings.PRIVATE_KEY_FILE):
        os.remove(settings.PRIVATE_KEY_FILE)

    private_key = get_fallback_private_key()
    account: ETHAccount = ETHAccount(private_key=private_key)

    mock_session = new_mock_session_with_post_success()

    new_post = await forget(
        account=account,
        hashes=["FAKE-HASH"],
        reason="GDPR",
        channel="TEST",
        session=mock_session,
        api_server="https://example.org",
    )

    assert mock_session.post.called
    assert isinstance(new_post, ForgetMessage)
    
@pytest.mark.asyncio
async def fetch_aggregate():
    
    _get_fallback_session.cache_clear()
    
    if os.path.exists(settings.PRIVATE_KEY_FILE):
            os.remove(settings.PRIVATE_KEY_FILE)

    private_key = get_fallback_private_key()
    account: ETHAccount = ETHAccount(private_key=private_key)
    
    mock_session = new_mock_session_with_post_success()

    address = account.get_address()
    
    response = await fetch_aggregate(
        address = address, 
        key = "0xa1B3bb7d2332383D96b7796B908fB7f7F3c2Be10",
        api_server = settings.API_HOST,
    )
