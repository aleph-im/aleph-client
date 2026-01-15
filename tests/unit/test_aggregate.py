from __future__ import annotations

import contextlib
import json
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from aleph_client.commands.aggregate import forget, get, list_aggregates, post

from .mocks import FAKE_ADDRESS_EVM, create_mock_load_account

FAKE_AGGREGATE_DATA = {
    "AI": {
        "subscription": "premium",
        "models": {
            "chatgpt": True,
            "claude": False,
            "libertai": True,
        },
        "active": True,
    },
}


@contextlib.asynccontextmanager
async def mock_client_session_get(self, aggr_link):
    yield AsyncMock(
        status=200,
        raise_for_status=MagicMock(),
        json=AsyncMock(return_value={"data": FAKE_AGGREGATE_DATA}),
    )


def create_mock_auth_client(return_fetch=FAKE_AGGREGATE_DATA):
    mock_auth_client = AsyncMock(
        create_aggregate=AsyncMock(return_value=(MagicMock(), "processed")),
        fetch_aggregate=AsyncMock(return_value=return_fetch),
    )
    mock_auth_client_class = MagicMock()
    mock_auth_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_auth_client)
    return mock_auth_client_class, mock_auth_client


def create_mock_client(return_fetch=FAKE_AGGREGATE_DATA):
    mock_auth_client = AsyncMock(
        fetch_aggregate=AsyncMock(return_value=return_fetch),
    )
    mock_auth_client_class = MagicMock()
    mock_auth_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_auth_client)
    return mock_auth_client_class, mock_auth_client


@pytest.mark.parametrize(
    ids=["by_key_only", "by_key_and_subkey", "by_key_and_subkeys"],
    argnames="args",
    argvalues=[
        {"key": "AI"},  # by key only
        {"key": "AI", "subkeys": "models"},  # with subkey
        {"key": "AI", "subkeys": "models,subscription"},  # with subkeys
    ],
)
@pytest.mark.asyncio
async def test_forget(capsys, args):
    mock_load_account = create_mock_load_account()
    mock_list_aggregates = AsyncMock(return_value=FAKE_AGGREGATE_DATA)
    mock_auth_client_class, mock_auth_client = create_mock_auth_client()

    @patch("aleph_client.commands.aggregate.load_account", mock_load_account)
    @patch("aleph_client.commands.aggregate.list_aggregates", mock_list_aggregates)
    @patch("aleph_client.commands.aggregate.AuthenticatedAlephHttpClient", mock_auth_client_class)
    async def run_forget(aggr_spec):
        print()  # For better display when pytest -v -s
        return await forget(**aggr_spec)

    result = await run_forget(args)
    assert result is True
    mock_load_account.assert_called_once()
    if "subkeys" not in args:
        mock_list_aggregates.assert_called_once()
    mock_auth_client.create_aggregate.assert_called_once()
    captured = capsys.readouterr()
    assert captured.out.endswith("has been deleted\n")


@pytest.mark.parametrize(
    ids=["by_key_only", "by_key_and_subkey"],
    argnames="args",
    argvalues=[
        {"key": "AI", "content": '{"test": "ok"}'},  # by key only
        {
            "key": "AI",
            "subkey": "models",
            "content": '{"chatgpt": true, "claude": true, "libertai": true}',
        },  # with subkey
    ],
)
@pytest.mark.asyncio
async def test_post(capsys, args):
    mock_load_account = create_mock_load_account()
    mock_auth_client_class, mock_auth_client = create_mock_auth_client()

    @patch("aleph_client.commands.aggregate.load_account", mock_load_account)
    @patch("aleph_client.commands.aggregate.AuthenticatedAlephHttpClient", mock_auth_client_class)
    async def run_post(aggr_spec):
        print()  # For better display when pytest -v -s
        return await post(**aggr_spec)

    result = await run_post(args)
    assert result is True
    mock_load_account.assert_called_once()
    mock_auth_client.create_aggregate.assert_called_once()
    captured = capsys.readouterr()
    assert captured.out.endswith("has been created/updated\n")


@pytest.mark.parametrize(
    ids=["by_key_only", "by_key_and_subkey", "by_key_and_subkeys"],
    argnames=["args", "expected"],
    argvalues=[
        ({"key": "AI"}, FAKE_AGGREGATE_DATA["AI"]),  # by key only
        (  # with subkey
            {"key": "AI", "subkeys": "subscription"},
            {"subscription": FAKE_AGGREGATE_DATA["AI"]["subscription"]},
        ),
        (  # with subkeys
            {"key": "AI", "subkeys": "subscription,models"},
            {"subscription": FAKE_AGGREGATE_DATA["AI"]["subscription"], "models": FAKE_AGGREGATE_DATA["AI"]["models"]},
        ),
    ],
)
@pytest.mark.asyncio
async def test_get(capsys, args, expected):
    mock_load_account = create_mock_load_account()
    mock_auth_class, mock__client = create_mock_auth_client(return_fetch=FAKE_AGGREGATE_DATA["AI"])

    @patch(
        "aleph_client.commands.aggregate.get_account_and_address",
        return_value=(mock_load_account.return_value, "test_address"),
    )
    @patch("aleph_client.commands.aggregate.AlephHttpClient", mock_auth_class)
    async def run_get(aggr_spec, mock_get_account):
        print()  # For better display when pytest -v -s
        return await get(**aggr_spec)

    aggregate = await run_get(args)
    mock__client.fetch_aggregate.assert_called_once()
    captured = capsys.readouterr()
    assert aggregate == expected and expected == json.loads(captured.out)


@pytest.mark.asyncio
async def test_get_with_ledger():
    """Test get aggregate using a Ledger hardware wallet."""
    # Mock configuration for Ledger device
    ledger_address = "0xdeadbeef1234567890123456789012345678beef"

    mock_client_class, mock_client = create_mock_client(return_fetch=FAKE_AGGREGATE_DATA["AI"])

    async def run_get_with_ledger():
        with patch("aleph_client.commands.aggregate.get_account_and_address", return_value=(None, ledger_address)):
            with patch("aleph_client.commands.aggregate.AlephHttpClient", mock_client_class):
                return await get(key="AI")

    # Call the function
    aggregate = await run_get_with_ledger()

    # Verify result
    assert aggregate == FAKE_AGGREGATE_DATA["AI"]
    # Verify that fetch_aggregate was called with the correct ledger address
    mock_client.fetch_aggregate.assert_called_with(address=ledger_address, key="AI")


@pytest.mark.asyncio
async def test_list_aggregates():
    mock_load_account = create_mock_load_account()

    @patch(
        "aleph_client.commands.aggregate.get_account_and_address",
        return_value=(mock_load_account.return_value, FAKE_ADDRESS_EVM),
    )
    @patch.object(aiohttp.ClientSession, "get", mock_client_session_get)
    async def run_list_aggregates(mock_get_account):
        print()  # For better display when pytest -v -s
        return await list_aggregates(address=FAKE_ADDRESS_EVM)

    aggregates = await run_list_aggregates()
    assert aggregates == FAKE_AGGREGATE_DATA


@pytest.mark.asyncio
async def test_list_aggregates_with_ledger():
    """Test listing aggregates using a Ledger hardware wallet."""
    # Mock configuration for Ledger device
    ledger_address = "0xdeadbeef1234567890123456789012345678beef"

    async def run_list_aggregates_with_ledger():
        with patch("aleph_client.commands.aggregate.get_account_and_address", return_value=(None, ledger_address)):
            with patch.object(aiohttp.ClientSession, "get", mock_client_session_get):
                return await list_aggregates()

    # Call the function
    aggregates = await run_list_aggregates_with_ledger()

    # Verify result
    assert aggregates == FAKE_AGGREGATE_DATA
