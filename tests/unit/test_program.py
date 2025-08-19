from __future__ import annotations

import contextlib
import random
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest
from aleph.sdk.conf import settings
from aleph_message.models import Chain

from aleph_client.commands.program import (
    delete,
    list_programs,
    logs,
    persist,
    runtime_checker,
    unpersist,
    update,
    upload,
)

from .mocks import (
    FAKE_ADDRESS_EVM,
    FAKE_PROGRAM_HASH,
    FAKE_PROGRAM_HASH_2,
    FAKE_STORE_HASH,
    FAKE_VM_HASH,
    Dict,
    create_mock_load_account,
)


def create_mock_program_message(
    mock_account, program_item_hash=None, internet=False, persistent=False, allow_amend=True
):
    if not program_item_hash:
        tmp = list(FAKE_PROGRAM_HASH)
        random.shuffle(tmp)
        program_item_hash = "".join(tmp)
    program = Dict(
        chain=Chain.ETH,
        sender=mock_account.get_address(),
        type="vm-function",
        channel="ALEPH-CLOUDSOLUTIONS",
        confirmed=True,
        item_type="inline",
        item_hash=program_item_hash,
        content=Dict(
            item_type="storage",  # for fake store message by convenience
            type="vm-function",
            address=mock_account.get_address(),
            time=1734037086.2333803,
            payment=Dict(chain=Chain.ETH, receiver=None, type="hold"),
            metadata={
                "name": f"mock_program{'_internet' if internet else ''}"
                f"{'_persistent' if persistent else ''}"
                f"{'_updatable' if allow_amend else ''}",
            },
            environment=Dict(internet=internet),
            resources=Dict(vcpus=1, memory=1024, seconds=30),
            volumes=[
                Dict(name="immutable", mount="/opt/packages", ref=FAKE_STORE_HASH),
                Dict(name="ephemeral", mount="/opt/temp", ephemeral=True, size_mib=1024),
                Dict(name="persistent", mount="/opt/utils", persistence=Dict(value="host"), size_mib=1024),
            ],
            code=Dict(encoding="squashfs", entrypoint="main:app", ref=FAKE_STORE_HASH),
            runtime=Dict(ref=FAKE_STORE_HASH),
            on=Dict(http=True, persistent=persistent),
            allow_amend=allow_amend,
        ),
    )
    return program


def create_mock_program_messages(mock_account):
    return AsyncMock(
        return_value=[
            create_mock_program_message(mock_account, allow_amend=False),
            create_mock_program_message(mock_account, internet=True, allow_amend=False),
            create_mock_program_message(mock_account, persistent=True, allow_amend=False),
            create_mock_program_message(mock_account),
        ]
    )


def create_mock_auth_client(mock_account, swap_persistent=False):
    mock_response_get_message = create_mock_program_message(mock_account, persistent=swap_persistent)
    mock_response_get_message_2 = create_mock_program_message(
        mock_account, program_item_hash=FAKE_PROGRAM_HASH_2, persistent=not swap_persistent
    )
    mock_auth_client = AsyncMock(
        get_messages=AsyncMock(),
        get_message=AsyncMock(return_value=mock_response_get_message),
        create_store=AsyncMock(return_value=[MagicMock(item_hash=FAKE_STORE_HASH), 200]),
        create_program=AsyncMock(return_value=[MagicMock(item_hash=FAKE_PROGRAM_HASH), 200]),
        forget=AsyncMock(return_value=(MagicMock(), 200)),
        submit=AsyncMock(return_value=[mock_response_get_message_2, 200, MagicMock()]),
        get_estimated_price=AsyncMock(
            return_value=MagicMock(
                required_tokens=1000,
                payment_type="hold",
            )
        ),
        get_program_price=AsyncMock(
            return_value=MagicMock(
                required_tokens=1000,
                payment_type="hold",
            )
        ),
    )
    mock_auth_client_class = MagicMock()
    mock_auth_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_auth_client)
    return mock_auth_client_class, mock_auth_client


@contextlib.asynccontextmanager
async def vm_client_operate(vm_id, operation, method="GET"):
    yield AsyncMock(
        url="https://crn.example.com",
        status=200,
        json=AsyncMock(
            return_value=[
                {
                    "__REALTIME_TIMESTAMP": "2024-02-02 23:34:21",
                    "MESSAGE": "hello world",
                }
            ]
        ),
    )


def create_mock_vm_client():
    mock_vm_client = AsyncMock(operate=vm_client_operate)
    mock_vm_client_class = MagicMock()
    mock_vm_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_vm_client)
    return mock_vm_client_class, mock_vm_client


@contextlib.asynccontextmanager
async def mock_client_session_get(self, program_url):
    yield AsyncMock(
        raise_for_status=MagicMock(),
        json=AsyncMock(
            return_value={
                "Distribution": "Debian GNU/Linux 12 (bookworm)",
                "Python": "3.11.2",
                "Docker": "Docker version 20.10.24+dfsg1, build 297e128",
                "Nodejs": "v18.13.0",
                "Rust": "Not installed",
                "Go": "Not installed",
            }
        ),
    )


@pytest.mark.asyncio
async def test_upload_program(mock_pricing_info_response):
    mock_load_account = create_mock_load_account()
    mock_account = mock_load_account.return_value
    mock_auth_client_class, mock_auth_client = create_mock_auth_client(mock_account)
    mock_get_balance = AsyncMock(return_value={"available_amount": 100000})

    @patch("aleph_client.commands.program._load_account", mock_load_account)
    @patch("aleph_client.utils.os.path.isfile", MagicMock(return_value=True))
    @patch("aleph_client.commands.program.AuthenticatedAlephHttpClient", mock_auth_client_class)
    @patch("aleph_client.commands.program.get_balance", mock_get_balance)
    @patch("aleph_client.commands.program.open", MagicMock())

    # Here we mock the info
    @patch.object(aiohttp.ClientSession, "get", return_value=mock_pricing_info_response)
    async def upload_program(_):
        print()  # For better display when pytest -v -s
        returned = await upload(
            address=FAKE_ADDRESS_EVM,
            path=Path("/fake/file.squashfs"),
            entrypoint="main:app",
            name="mock_program",
            runtime=settings.DEFAULT_RUNTIME_ID,
            compute_units=1,
            updatable=True,
            skip_volume=True,
            skip_env_var=True,
        )
        mock_load_account.assert_called_once()
        mock_auth_client.create_store.assert_called_once()
        mock_get_balance.assert_called_once()
        mock_auth_client.get_estimated_price.assert_called_once()
        mock_auth_client.create_program.assert_called_once()
        assert returned == FAKE_PROGRAM_HASH

    await upload_program()


@pytest.mark.asyncio
async def test_update_program():
    mock_load_account = create_mock_load_account()
    mock_account = mock_load_account.return_value
    mock_auth_client_class, mock_auth_client = create_mock_auth_client(mock_account)

    @patch("aleph_client.commands.program._load_account", mock_load_account)
    @patch("aleph_client.utils.os.path.isfile", MagicMock(return_value=True))
    @patch("aleph_client.commands.program.AuthenticatedAlephHttpClient", mock_auth_client_class)
    @patch("aleph_client.commands.program.open", MagicMock())
    async def update_program():
        print()  # For better display when pytest -v -s
        await update(item_hash=FAKE_PROGRAM_HASH, path=Path("/fake/file.squashfs"))
        mock_load_account.assert_called_once()
        assert mock_auth_client.get_message.call_count == 2
        mock_auth_client.create_store.assert_called_once()

    await update_program()


@pytest.mark.asyncio
async def test_delete_program():
    mock_load_account = create_mock_load_account()
    mock_account = mock_load_account.return_value
    mock_auth_client_class, mock_auth_client = create_mock_auth_client(mock_account)

    @patch("aleph_client.commands.program._load_account", mock_load_account)
    @patch("aleph_client.commands.program.AuthenticatedAlephHttpClient", mock_auth_client_class)
    async def delete_program():
        print()  # For better display when pytest -v -s
        await delete(item_hash=FAKE_PROGRAM_HASH)
        mock_load_account.assert_called_once()
        assert mock_auth_client.get_message.call_count == 2
        assert mock_auth_client.forget.call_count == 2

    await delete_program()


@pytest.mark.asyncio
async def test_list_programs():
    mock_load_account = create_mock_load_account()
    mock_account = mock_load_account.return_value
    mock_auth_client_class, mock_auth_client = create_mock_auth_client(mock_account)
    mock_program_messages = create_mock_program_messages(mock_account)

    @patch("aleph_client.commands.program._load_account", mock_load_account)
    @patch("aleph_client.commands.program.AlephHttpClient", mock_auth_client_class)
    @patch("aleph_client.commands.program.filter_only_valid_messages", mock_program_messages)
    async def list_program():
        print()  # For better display when pytest -v -s
        await list_programs(address=mock_account.get_address())
        mock_program_messages.assert_called_once()
        mock_auth_client.get_messages.assert_called_once()
        assert mock_auth_client.get_program_price.call_count == 4

    await list_program()


@pytest.mark.asyncio
async def test_persist_program():
    mock_load_account = create_mock_load_account()
    mock_account = mock_load_account.return_value
    mock_auth_client_class, mock_auth_client = create_mock_auth_client(mock_account)

    @patch("aleph_client.commands.program._load_account", mock_load_account)
    @patch("aleph_client.commands.program.AuthenticatedAlephHttpClient", mock_auth_client_class)
    async def persist_program():
        print()  # For better display when pytest -v -s
        returned = await persist(item_hash=FAKE_PROGRAM_HASH)
        mock_load_account.assert_called_once()
        mock_auth_client.get_message.assert_called_once()
        mock_auth_client.submit.assert_called_once()
        mock_auth_client.forget.assert_called_once()
        assert returned == FAKE_PROGRAM_HASH_2

    await persist_program()


@pytest.mark.asyncio
async def test_unpersist_program():
    mock_load_account = create_mock_load_account()
    mock_account = mock_load_account.return_value
    mock_auth_client_class, mock_auth_client = create_mock_auth_client(mock_account, swap_persistent=True)

    @patch("aleph_client.commands.program._load_account", mock_load_account)
    @patch("aleph_client.commands.program.AuthenticatedAlephHttpClient", mock_auth_client_class)
    async def unpersist_program():
        print()  # For better display when pytest -v -s
        returned = await unpersist(item_hash=FAKE_PROGRAM_HASH)
        mock_load_account.assert_called_once()
        mock_auth_client.get_message.assert_called_once()
        mock_auth_client.submit.assert_called_once()
        mock_auth_client.forget.assert_called_once()
        assert returned == FAKE_PROGRAM_HASH_2

    await unpersist_program()


@pytest.mark.asyncio
async def test_logs_program(capsys):
    mock_load_account = create_mock_load_account()
    mock_vm_client_class, _ = create_mock_vm_client()

    @patch("aleph_client.commands.program._load_account", mock_load_account)
    @patch("aleph_client.commands.program.VmClient", mock_vm_client_class)
    async def logs_program():
        print()  # For better display when pytest -v -s
        await logs(
            FAKE_VM_HASH,
            domain="https://crn.example.com",
            chain=Chain.ETH,
        )

    await logs_program()
    captured = capsys.readouterr()
    assert captured.out == "\nReceived logs\n2024-02-02 23:34:21>  hello world\n"


@pytest.mark.asyncio
async def test_runtime_checker_program():
    mock_upload = AsyncMock(return_value=FAKE_PROGRAM_HASH)
    mock_delete = AsyncMock()

    @patch("aleph_client.commands.program.upload", mock_upload)
    @patch.object(aiohttp.ClientSession, "get", mock_client_session_get)
    @patch("aleph_client.commands.program.delete", mock_delete)
    async def runtime_checker_program():
        print()  # For better display when pytest -v -s
        await runtime_checker(item_hash=FAKE_STORE_HASH)
        mock_upload.assert_called_once()
        mock_delete.assert_called_once()

    await runtime_checker_program()
