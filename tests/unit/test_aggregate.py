from __future__ import annotations

import contextlib
import json
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from aleph_client.commands.aggregate import (
    authorize,
    forget,
    get,
    list_aggregates,
    permissions,
    post,
    revoke,
)

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
    "security": {"authorizations": [{"address": FAKE_ADDRESS_EVM, "types": ["POST"]}]},
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

    @patch("aleph_client.commands.aggregate._load_account", mock_load_account)
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
        {"key": "AI", "subkey": "models", "content": '{"chatgpt": true, "claude": true, "libertai": true}'},  # with subkey
    ],
)
@pytest.mark.asyncio
async def test_post(capsys, args):
    mock_load_account = create_mock_load_account()
    mock_auth_client_class, mock_auth_client = create_mock_auth_client()

    @patch("aleph_client.commands.aggregate._load_account", mock_load_account)
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
            {"subscription": FAKE_AGGREGATE_DATA["AI"]["subscription"]},  # type: ignore
        ),
        (  # with subkeys
            {"key": "AI", "subkeys": "subscription,models"},
            {"subscription": FAKE_AGGREGATE_DATA["AI"]["subscription"], "models": FAKE_AGGREGATE_DATA["AI"]["models"]},  # type: ignore
        ),
    ],
)
@pytest.mark.asyncio
async def test_get(capsys, args, expected):
    mock_load_account = create_mock_load_account()
    mock_auth_client_class, mock_auth_client = create_mock_auth_client(return_fetch=FAKE_AGGREGATE_DATA["AI"])

    @patch("aleph_client.commands.aggregate._load_account", mock_load_account)
    @patch("aleph_client.commands.aggregate.AuthenticatedAlephHttpClient", mock_auth_client_class)
    async def run_get(aggr_spec):
        print()  # For better display when pytest -v -s
        return await get(**aggr_spec)

    aggregate = await run_get(args)
    mock_load_account.assert_called_once()
    mock_auth_client.fetch_aggregate.assert_called_once()
    captured = capsys.readouterr()
    assert aggregate == expected and expected == json.loads(captured.out)


@pytest.mark.asyncio
async def test_list_aggregates():
    mock_load_account = create_mock_load_account()

    @patch("aleph_client.commands.aggregate._load_account", mock_load_account)
    @patch.object(aiohttp.ClientSession, "get", mock_client_session_get)
    async def run_list_aggregates():
        print()  # For better display when pytest -v -s
        return await list_aggregates(address=FAKE_ADDRESS_EVM)

    aggregates = await run_list_aggregates()
    mock_load_account.assert_called_once()
    assert aggregates == FAKE_AGGREGATE_DATA


@pytest.mark.asyncio
async def test_authorize(capsys):
    mock_load_account = create_mock_load_account()
    mock_get = AsyncMock(return_value=FAKE_AGGREGATE_DATA["security"])
    mock_post = AsyncMock(return_value=True)

    @patch("aleph_client.commands.aggregate._load_account", mock_load_account)
    @patch("aleph_client.commands.aggregate.get", mock_get)
    @patch("aleph_client.commands.aggregate.post", mock_post)
    async def run_authorize():
        print()  # For better display when pytest -v -s
        return await authorize(address=FAKE_ADDRESS_EVM, types="PROGRAM,FORGET")

    await run_authorize()
    mock_load_account.assert_called_once()
    mock_get.assert_called_once()
    mock_post.assert_called_once()
    captured = capsys.readouterr()
    assert captured.out.endswith(f"Permissions has been added for {FAKE_ADDRESS_EVM}\n")


@pytest.mark.asyncio
async def test_revoke(capsys):
    mock_load_account = create_mock_load_account()
    mock_get = AsyncMock(return_value=FAKE_AGGREGATE_DATA["security"])
    mock_post = AsyncMock(return_value=True)

    @patch("aleph_client.commands.aggregate._load_account", mock_load_account)
    @patch("aleph_client.commands.aggregate.get", mock_get)
    @patch("aleph_client.commands.aggregate.post", mock_post)
    async def run_revoke():
        print()  # For better display when pytest -v -s
        return await revoke(address=FAKE_ADDRESS_EVM)

    await run_revoke()
    mock_load_account.assert_called_once()
    mock_get.assert_called_once()
    mock_post.assert_called_once()
    captured = capsys.readouterr()
    assert captured.out.endswith(f"Permissions has been deleted for {FAKE_ADDRESS_EVM}\n")


@pytest.mark.asyncio
async def test_permissions():
    mock_load_account = create_mock_load_account()
    mock_get = AsyncMock(return_value=FAKE_AGGREGATE_DATA["security"])

    @patch("aleph_client.commands.aggregate._load_account", mock_load_account)
    @patch("aleph_client.commands.aggregate.get", mock_get)
    async def run_permissions():
        print()  # For better display when pytest -v -s
        return await permissions(address=FAKE_ADDRESS_EVM, json=True)

    authorizations = await run_permissions()
    mock_load_account.assert_called_once()
    mock_get.assert_called_once()
    assert authorizations == FAKE_AGGREGATE_DATA["security"]["authorizations"]  # type: ignore
