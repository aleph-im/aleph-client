from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aleph_client.commands.authorizations import add as add_authorization
from aleph_client.commands.authorizations import list as list_authorizations
from aleph_client.commands.authorizations import revoke as revoke_authorization

from .mocks import FAKE_ADDRESS_EVM, create_mock_load_account

FAKE_AUTHORIZATIONS = [{"address": FAKE_ADDRESS_EVM, "types": ["POST"]}]


def create_mock_aleph_http_client(authorizations=None):
    """Create a mock AlephHttpClient with get_authorizations mocked."""
    mock_client = AsyncMock()
    mock_client.get_authorizations = AsyncMock(return_value=authorizations or [])

    mock_client_class = MagicMock()
    mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)
    return mock_client_class, mock_client


def create_mock_authenticated_aleph_http_client():
    """Create a mock AuthenticatedAlephHttpClient with add_authorization and revoke methods."""
    mock_client = AsyncMock()
    mock_client.add_authorization = AsyncMock(return_value=None)
    mock_client.revoke_all_authorizations = AsyncMock(return_value=None)
    mock_client.update_all_authorizations = AsyncMock(return_value=None)

    mock_client_class = MagicMock()
    mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)
    return mock_client_class, mock_client


@pytest.mark.asyncio
async def test_authorize(capsys):
    mock_load_account = create_mock_load_account()
    mock_auth_client_class, mock_auth_client = create_mock_authenticated_aleph_http_client()

    @patch("aleph_client.commands.authorizations.load_account", mock_load_account)
    @patch("aleph_client.commands.authorizations.AuthenticatedAlephHttpClient", mock_auth_client_class)
    async def run_authorize():
        print()  # For better display when pytest -v -s
        return await add_authorization(delegate_address=FAKE_ADDRESS_EVM, message_types="PROGRAM,FORGET")

    await run_authorize()
    mock_load_account.assert_called_once()
    mock_auth_client.add_authorization.assert_called_once()
    captured = capsys.readouterr()
    assert f"Added authorization for {FAKE_ADDRESS_EVM}" in captured.out


@pytest.mark.asyncio
async def test_revoke(capsys):
    mock_load_account = create_mock_load_account()
    mock_auth_client_class, mock_auth_client = create_mock_authenticated_aleph_http_client()

    @patch("aleph_client.commands.authorizations.load_account", mock_load_account)
    @patch("aleph_client.commands.authorizations.AuthenticatedAlephHttpClient", mock_auth_client_class)
    async def run_revoke():
        print()  # For better display when pytest -v -s
        return await revoke_authorization(delegate_address=FAKE_ADDRESS_EVM)

    await run_revoke()
    mock_load_account.assert_called_once()
    mock_auth_client.revoke_all_authorizations.assert_called_once_with(FAKE_ADDRESS_EVM)
    captured = capsys.readouterr()
    assert f"Revoked authorizations for {FAKE_ADDRESS_EVM}" in captured.out


@pytest.mark.asyncio
async def test_permissions():
    mock_load_account = create_mock_load_account()

    # Create a mock authorization object with necessary attributes
    mock_authorization = MagicMock()
    mock_authorization.address = FAKE_ADDRESS_EVM
    mock_authorization.chain = None
    mock_authorization.channels = []
    mock_authorization.types = [MagicMock(value="POST")]
    mock_authorization.post_types = []
    mock_authorization.aggregate_keys = []

    mock_client_class, mock_client = create_mock_aleph_http_client(authorizations=[mock_authorization])

    @patch("aleph_client.commands.authorizations.load_account", mock_load_account)
    @patch("aleph_client.commands.authorizations.AlephHttpClient", mock_client_class)
    async def run_list_authorizations():
        print()  # For better display when pytest -v -s
        return await list_authorizations(address=FAKE_ADDRESS_EVM, json=True)

    await run_list_authorizations()
    mock_client.get_authorizations.assert_called_once_with(FAKE_ADDRESS_EVM)
