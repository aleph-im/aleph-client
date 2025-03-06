import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.conf import settings
from typer.testing import CliRunner

from aleph_client.__main__ import app

from .mocks import (
    FAKE_STORE_HASH,
    FAKE_STORE_HASH_CONTENT_FILE_CID,
    FAKE_STORE_HASH_PUBLISHER,
)

runner = CliRunner()


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


def test_account_balance(env_files):
    settings.CONFIG_FILE = env_files[1]
    result = runner.invoke(
        app, ["account", "balance", "--address", "0xCAfEcAfeCAfECaFeCaFecaFecaFECafECafeCaFe", "--chain", "ETH"]
    )
    assert result.exit_code == 0
    assert result.stdout.startswith("╭─ Account Infos")


def test_account_config(env_files):
    settings.CONFIG_FILE = env_files[1]
    result = runner.invoke(app, ["account", "config", "--private-key-file", str(env_files[0]), "--chain", "ETH"])
    assert result.exit_code == 0
    assert result.stdout.startswith("New Default Configuration: ")


def test_message_get():
    # Use subprocess to avoid border effects between tests caused by the initialisation
    # of the aiohttp client session out of an async context in the SDK. This avoids
    # a "no running event loop" error when running several tests back to back.
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


def test_message_find():
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


def test_post_message(env_files):
    settings.CONFIG_FILE = env_files[1]
    test_file_path = Path(__file__).parent.parent / "test_post.json"
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
    assert result.return_value.dict()["hash"] == FAKE_STORE_HASH_CONTENT_FILE_CID


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
