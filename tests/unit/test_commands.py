import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from unittest.mock import AsyncMock

import pytest
from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.conf import settings
from aleph.sdk.query.responses import MessagesResponse
from aleph_message.models import PostMessage, StoreMessage
from typer.testing import CliRunner

from aleph_client.__main__ import app

from .mocks import (
    FAKE_STORE_HASH,
    FAKE_STORE_HASH_CONTENT_FILE_CID,
    FAKE_STORE_HASH_PUBLISHER,
)

runner = CliRunner()


@pytest.fixture
def store_message_fixture():
    return {
        "sender": "0xe0aaF578B287de16852dbc54Ae34a263FF2F4b9E",
        "chain": "ETH",
        "signature": "0xe2d0bd0476e73652b1dbac082f250387b0a7691ee19f39ad6ffce2e8a45028160f3e35ef346beb4a4b5f"
        "50aacdd0d9b454f63eeedc3f8058eb25f7b096eadd231c",
        "type": "STORE",
        "item_content": '{"item_type":"ipfs","item_hash":"QmXSEnpQCnUfeGFoSjY1XAK1Cuad5CtAaqyachGTtsFSuA",'
        '"ref":"0xd8058efe0198ae9dd7d563e1b4938dcbc86a1f81:14",'
        '"address":"0xe0aaF578B287de16852dbc54Ae34a263FF2F4b9E","time":1738837907}',
        "item_type": "inline",
        "item_hash": "5b868dc8c2df0dd9bb810b7a31cc50c8ad1e6569905e45ab4fd2eee36fecc4d2",
        "time": 1738837907,
        "channel": "test-chan-1",
        "content": {
            "address": "0xe0aaF578B287de16852dbc54Ae34a263FF2F4b9E",
            "time": 1738837907,
            "item_type": "ipfs",
            "item_hash": "QmXSEnpQCnUfeGFoSjY1XAK1Cuad5CtAaqyachGTtsFSuA",
            "size": None,
            "content_type": None,
            "ref": "0xd8058efe0198ae9dd7d563e1b4938dcbc86a1f81:14",
            "metadata": None,
        },
    }


async def create_mock_http_response(status_code=200, response_data=None):
    resp = AsyncMock(status=status_code)
    resp.status = status_code
    resp.json.return_value = response_data
    return resp


def get_account(my_account_file: Path) -> ETHAccount:
    with open(my_account_file, "rb") as fd:
        private_key = fd.read()
    return ETHAccount(private_key=private_key)


def get_test_message(account: ETHAccount):
    return {
        "chain": "ETH",
        "sender": account.get_address(),
        "type": "AGGREGATE",
        "item_hash": "0x1234",
    }


def test_account_create(env_files):
    settings.CONFIG_FILE = env_files[1]
    old_key = env_files[0].read_bytes()
    result = runner.invoke(
        app,
        ["account", "create", "--replace", "--private-key-file", str(env_files[0]), "--chain", "ETH"],
    )
    assert result.exit_code == 0, result.stdout
    new_key = env_files[0].read_bytes()
    assert new_key != old_key


def test_account_import_evm(env_files):
    settings.CONFIG_FILE = env_files[1]
    old_key = env_files[0].read_bytes()
    result = runner.invoke(
        app,
        [
            "account",
            "create",
            "--replace",
            "--private-key-file",
            str(env_files[0]),
            "--chain",
            "ETH",
            "--private-key",
            "0x5f5da4cee72286b9aec06fffe130e04e4b35583c1bf28b4d1992f6d69df1e076",
        ],
    )
    assert result.exit_code == 0, result.stdout
    new_key = env_files[0].read_bytes()
    assert new_key != old_key


def test_account_import_evm_base32(env_files):
    settings.CONFIG_FILE = env_files[1]
    old_key = env_files[0].read_bytes()
    result = runner.invoke(
        app,
        [
            "account",
            "create",
            "--replace",
            "--private-key-file",
            str(env_files[0]),
            "--chain",
            "ETH",
            "--private-key",
            "JXINYIKE2QOUXCZRAFA2FG4AMYYPEOLS4OIGEZ2WK4WCQDWYSAMQ====",
            "--key-format",
            "base32",
        ],
    )
    assert result.exit_code == 0, result.stdout
    new_key = env_files[0].read_bytes()
    assert new_key != old_key


def test_account_import_evm_base64(env_files):
    settings.CONFIG_FILE = env_files[1]
    old_key = env_files[0].read_bytes()
    result = runner.invoke(
        app,
        [
            "account",
            "create",
            "--replace",
            "--private-key-file",
            str(env_files[0]),
            "--chain",
            "ETH",
            "--private-key",
            "TdDcIUTUHUuLMQFBopuAZjDyOXLjkGJnVlcsKA7YkBk=",
            "--key-format",
            "base64",
        ],
    )
    assert result.exit_code == 0, result.stdout
    new_key = env_files[0].read_bytes()
    assert new_key != old_key


def test_account_import_evm_format_invalid(env_files):
    """Test that an invalid key format raises an error."""
    settings.CONFIG_FILE = env_files[1]
    result = runner.invoke(
        app,
        [
            "account",
            "create",
            "--replace",
            "--private-key-file",
            str(env_files[0]),
            "--chain",
            "ETH",
            "--private-key",
            "TdDcIUTUHUuLMQFBopuAZjDyOXLjkGJnVlcsKA7YkBk=",
            "--key-format",
            "invalid",
        ],
    )
    assert result.exit_code != 0, result.stdout


def test_account_import_sol(env_files):
    settings.CONFIG_FILE = env_files[1]
    old_key = env_files[0].read_bytes()
    result = runner.invoke(
        app,
        [
            "account",
            "create",
            "--replace",
            "--private-key-file",
            str(env_files[0]),
            "--chain",
            "SOL",
            "--private-key",
            "2ub2ka8FFjDtfz5m9i2N6HvurgHaHDPD1nwVdmWy7ZhvMvGWbxaAMaPn8RECCerzo9Au2AToPXHzE6jsjjWscnHt",
        ],
    )
    assert result.exit_code == 0, result.stdout
    new_key = env_files[0].read_bytes()
    assert new_key != old_key


def test_account_address(env_files):
    settings.CONFIG_FILE = env_files[1]
    result = runner.invoke(app, ["account", "address", "--private-key-file", str(env_files[0])])
    assert result.exit_code == 0
    assert result.stdout.startswith("✉  Addresses for Active Account ✉\n\nEVM: 0x")


def test_account_chain(env_files):
    settings.CONFIG_FILE = env_files[1]
    result = runner.invoke(app, ["account", "chain"])
    assert result.exit_code == 0
    assert result.stdout.startswith("Active Chain:")


def test_account_path():
    result = runner.invoke(app, ["account", "path"])
    assert result.exit_code == 0
    assert result.stdout.startswith("Aleph Home directory: ")


def test_account_show(env_files):
    settings.CONFIG_FILE = env_files[1]
    result = runner.invoke(app, ["account", "show", "--private-key-file", str(env_files[0])])
    assert result.exit_code == 0
    assert result.stdout.startswith("✉  Addresses for Active Account ✉\n\nEVM: 0x")


def test_account_export_private_key(env_files):
    settings.CONFIG_FILE = env_files[1]
    result = runner.invoke(app, ["account", "export-private-key", "--private-key-file", str(env_files[0])])
    assert result.exit_code == 0
    assert result.stdout.startswith("⚠️  Private Keys for Active Account ⚠️\n\nEVM: 0x")


def test_account_list(env_files):
    settings.CONFIG_FILE = env_files[1]
    result = runner.invoke(app, ["account", "list"])
    assert result.exit_code == 0
    assert result.stdout.startswith("🌐  Chain Infos 🌐")


def test_account_sign_bytes(env_files):
    settings.CONFIG_FILE = env_files[1]
    result = runner.invoke(app, ["account", "sign-bytes", "--message", "test", "--chain", "ETH"])
    assert result.exit_code == 0
    assert result.stdout.startswith("\nSignature:")


def test_account_balance(mocker, env_files):
    settings.CONFIG_FILE = env_files[1]
    balance_response = {
        "address": "0xCAfEcAfeCAfECaFeCaFecaFecaFECafECafeCaFe",
        "balance": 24853,
        "details": {"AVAX": 4000, "BASE": 10000, "ETH": 10853},
        "locked_amount": 4663.334518051392,
        "available_amount": 20189.665481948608,
    }

    mocker.patch("aleph_client.commands.account.get_balance", return_value=balance_response)
    mocker.patch("aleph_client.voucher.VoucherManager.get_all", return_value=[])

    result = runner.invoke(
        app, ["account", "balance", "--address", "0xCAfEcAfeCAfECaFeCaFecaFecaFECafECafeCaFe", "--chain", "ETH"]
    )
    assert result.exit_code == 0
    assert result.stdout.startswith("╭─ Account Infos")
    assert "Available: 20189.67" in result.stdout


def test_account_config(env_files):
    settings.CONFIG_FILE = env_files[1]
    result = runner.invoke(app, ["account", "config", "--private-key-file", str(env_files[0]), "--chain", "ETH"])
    assert result.exit_code == 0
    assert result.stdout.startswith("New Default Configuration: ")


def test_message_get(mocker, store_message_fixture):
    # Use subprocess to avoid border effects between tests caused by the initialisation
    # of the aiohttp client session out of an async context in the SDK. This avoids
    # a "no running event loop" error when running several tests back to back.

    message = StoreMessage.model_validate(store_message_fixture)
    mocker.patch("aleph.sdk.AlephHttpClient.get_message", return_value=[message, "processed"])

    result = runner.invoke(
        app,
        [
            "message",
            "get",
            FAKE_STORE_HASH,
        ],
    )
    assert result.exit_code == 0
    assert FAKE_STORE_HASH_PUBLISHER in result.stdout


def test_message_find(mocker, store_message_fixture):
    response = {
        "messages": [store_message_fixture],
        "pagination_per_page": 20,
        "pagination_page": 1,
        "pagination_total": 1,
        "pagination_item": "messages",
    }
    messages = MessagesResponse.model_validate(response)
    mocker.patch("aleph.sdk.AlephHttpClient.get_messages", return_value=messages)

    result = runner.invoke(
        app,
        [
            "message",
            "find",
            "--pagination=1",
            "--page=1",
            "--start-date=1234",
            "--chains=ETH",
            f"--hashes={FAKE_STORE_HASH}",
        ],
    )
    assert result.exit_code == 0
    assert FAKE_STORE_HASH_PUBLISHER in result.stdout
    assert FAKE_STORE_HASH in result.stdout


def test_post_message(mocker, env_files):
    settings.CONFIG_FILE = env_files[1]
    test_file_path = Path(__file__).parent.parent / "test_post.json"

    post_message_text = json.loads(test_file_path.read_text())
    post_message = {
        "type": "POST",
        "chain": "ETH",
        "sender": "0xe0aaF578B287de16852dbc54Ae34a263FF2F4b9E",
        "signature": "0xe2d0bd0476e73652b1dbac082f250387b0a7691ee19f39ad6ffce2e8a45028160f3e35ef346beb4a4b5f50"
        "aacdd0d9b454f63eeedc3f8058eb25f7b096eadd231c",
        "item_type": "inline",
        "item_content": json.dumps(post_message_text),
        "item_hash": "eddec2643cadc2d895ddb399499b0b2cd72ce7122080e0c78f833d1d959f5f82",
        "content": {
            "address": "0x40684b43B88356F62DCc56017547B6A7AC68780B",
            "time": 1755201350,
            "content": post_message_text,
            "type": "test",
        },
        "time": 1738837907,
        "channel": "test-chan-1",
        "size": 208,
    }
    message = PostMessage.model_validate(post_message)
    mocker.patch("aleph.sdk.AuthenticatedAlephHttpClient.create_post", return_value=[message, "processed"])

    result = runner.invoke(
        app,
        [
            "message",
            "post",
            "--private-key-file",
            str(env_files[0]),
            "--path",
            str(test_file_path),
        ],
    )
    assert result.exit_code == 0
    assert "item_hash" in result.stdout


def test_sign_message(env_files):
    settings.CONFIG_FILE = env_files[1]
    account = get_account(env_files[0])
    message = get_test_message(account)
    result = runner.invoke(
        app,
        [
            "message",
            "sign",
            "--private-key-file",
            str(env_files[0]),
            "--message",
            json.dumps(message),
        ],
    )

    assert result.exit_code == 0
    assert "signature" in result.stdout


def test_sign_message_stdin(env_files):
    settings.CONFIG_FILE = env_files[1]
    account = get_account(env_files[0])
    message = get_test_message(account)
    result = runner.invoke(
        app,
        [
            "message",
            "sign",
            "--private-key-file",
            str(env_files[0]),
        ],
        input=json.dumps(message),
    )

    assert result.exit_code == 0
    assert "signature" in result.stdout


def test_sign_raw():
    result = runner.invoke(
        app,
        [
            "account",
            "sign-bytes",
            "--message",
            "some message",
        ],
    )

    assert result.exit_code == 0
    assert "0x" in result.stdout


def test_sign_raw_stdin():
    message = "some message"
    result = runner.invoke(
        app,
        [
            "account",
            "sign-bytes",
        ],
        input=message,
    )

    assert result.exit_code == 0
    assert "0x" in result.stdout


def test_file_upload():
    # Test upload a file to aleph network by creating a file and upload it to an aleph node
    with NamedTemporaryFile() as temp_file:
        temp_file.write(b"Hello World \n")
        result = runner.invoke(
            app,
            ["file", "upload", temp_file.name],
        )
        assert result.exit_code == 0
        assert result.stdout is not None


def test_file_download():
    # Test download a file from aleph network
    ipfs_cid = "QmeomffUNfmQy76CQGy9NdmqEnnHU9soCexBnGU3ezPHVH"
    result = runner.invoke(
        app,
        [
            "file",
            "download",
            ipfs_cid,
        ],  # 5 bytes file
    )
    assert result.exit_code == 0
    assert result.stdout is not None
    os.remove(ipfs_cid)


def test_file_download_only_info():
    # Test retrieve the underlying content cid
    result = runner.invoke(
        app,
        [
            "file",
            "download",
            FAKE_STORE_HASH,
            "--only-info",
        ],
        standalone_mode=False,
    )
    assert result.exit_code == 0
    assert result.return_value.model_dump()["hash"] == FAKE_STORE_HASH_CONTENT_FILE_CID


def test_file_list():
    result = runner.invoke(
        app,
        [
            "file",
            "list",
        ],
    )

    assert result.exit_code == 0
    assert "0x" in result.stdout
