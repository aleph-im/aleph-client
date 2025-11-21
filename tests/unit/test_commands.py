import hashlib
import json
from pathlib import Path
from tempfile import NamedTemporaryFile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.conf import AccountType, MainConfiguration, settings
from aleph.sdk.exceptions import (
    ForgottenMessageError,
    MessageNotFoundError,
    RemovedMessageError,
)
from aleph.sdk.query.responses import MessagesResponse
from aleph.sdk.types import StorageEnum, StoredContent
from aleph_message.models import Chain, PostMessage, StoreMessage
from typer.testing import CliRunner

from aleph_client.__main__ import app
from aleph_client.commands.files import upload

from .mocks import FAKE_STORE_HASH, FAKE_STORE_HASH_PUBLISHER
from .test_instance import create_mock_client

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


@patch("aleph.sdk.wallets.ledger.ethereum.LedgerETHAccount.get_accounts")
def test_account_address(mock_get_accounts, env_files):
    settings.CONFIG_FILE = env_files[1]
    result = runner.invoke(app, ["account", "address", "--private-key-file", str(env_files[0])])
    assert result.exit_code == 0
    assert result.stdout.startswith("✉  Addresses for Active Account ✉\n\nEVM: 0x")

    # Test with ledger device
    mock_ledger_account = MagicMock()
    mock_ledger_account.address = "0xdeadbeef1234567890123456789012345678beef"
    mock_ledger_account.get_address.return_value = "0xdeadbeef1234567890123456789012345678beef"
    mock_get_accounts.return_value = [mock_ledger_account]

    # Create a ledger config
    ledger_config = MainConfiguration(
        path=None, chain=Chain.ETH, type=AccountType.HARDWARE, address=mock_ledger_account.address
    )

    with patch("aleph_client.commands.account.load_main_configuration", return_value=ledger_config):
        with patch(
            "aleph_client.commands.account.load_account",
            side_effect=lambda _, __, chain: (
                mock_ledger_account if chain == Chain.ETH else Exception("Ledger doesn't support SOL")
            ),
        ):
            result = runner.invoke(app, ["account", "address"])
            assert result.exit_code == 0
            assert result.stdout.startswith("✉  Addresses for Active Account (Ledger) ✉\n\nEVM: 0x")


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


def test_account_export_private_key_ledger():
    """Test that export-private-key fails for Ledger devices."""
    # Create a ledger config
    ledger_config = MainConfiguration(
        path=None, chain=Chain.ETH, type=AccountType.HARDWARE, address="0xdeadbeef1234567890123456789012345678beef"
    )

    with patch("aleph_client.commands.account.load_main_configuration", return_value=ledger_config):
        result = runner.invoke(app, ["account", "export-private-key"])

        # Command should fail with appropriate message
        assert result.exit_code == 1
        assert "Cannot export private key from a Ledger hardware wallet" in result.stdout
        assert "The private key remains securely stored on your Ledger device" in result.stdout


def test_account_list(env_files):
    settings.CONFIG_FILE = env_files[1]
    result = runner.invoke(app, ["account", "list"])
    assert result.exit_code == 0
    assert result.stdout.startswith("🌐  Chain Infos 🌐")


@patch("aleph.sdk.wallets.ledger.ethereum.LedgerETHAccount.get_accounts")
def test_account_list_with_ledger(mock_get_accounts):
    """Test that account list shows Ledger devices when available."""
    # Create mock Ledger accounts
    mock_account1 = MagicMock()
    mock_account1.address = "0xdeadbeef1234567890123456789012345678beef"
    mock_account2 = MagicMock()
    mock_account2.address = "0xcafebabe5678901234567890123456789012cafe"
    mock_get_accounts.return_value = [mock_account1, mock_account2]

    # Test with no configuration first
    with patch("aleph_client.commands.account.load_main_configuration", return_value=None):
        result = runner.invoke(app, ["account", "list"])
        assert result.exit_code == 0

        # Check that the ledger accounts are listed
        assert "Ledger #0" in result.stdout
        assert "Ledger #1" in result.stdout
        assert mock_account1.address in result.stdout
        assert mock_account2.address in result.stdout

    # Test with a ledger account that's active in configuration
    ledger_config = MainConfiguration(
        path=None, chain=Chain.ETH, type=AccountType.HARDWARE, address=mock_account1.address
    )

    with patch("aleph_client.commands.account.load_main_configuration", return_value=ledger_config):
        result = runner.invoke(app, ["account", "list"])
        assert result.exit_code == 0

        # Check that the active ledger account is marked
        assert "Ledger" in result.stdout
        assert mock_account1.address in result.stdout
        # Just check for asterisk since rich formatting tags may not be visible in test output
        assert "*" in result.stdout


def test_account_sign_bytes(env_files):
    settings.CONFIG_FILE = env_files[1]
    result = runner.invoke(app, ["account", "sign-bytes", "--message", "test", "--chain", "ETH"])
    assert result.exit_code == 0
    assert result.stdout.startswith("\nSignature:")


def test_account_balance(mocker, env_files, mock_voucher_service, mock_get_balances):
    """
    This test verifies that the account balance command correctly displays balance and voucher information.
    """

    settings.CONFIG_FILE = env_files[1]
    mock_client_class, mock_client = create_mock_client(None, None, mock_get_balances=mock_get_balances)

    mock_client.voucher = mock_voucher_service

    mocker.patch("aleph_client.commands.account.AlephHttpClient", mock_client_class)

    result = runner.invoke(
        app, ["account", "balance", "--address", "0xCAfEcAfeCAfECaFeCaFecaFecaFECafECafeCaFe", "--chain", "ETH"]
    )

    assert result.exit_code == 0
    assert result.stdout.startswith("╭─ Account Infos")
    assert "Available: 20189.67" in result.stdout
    assert "Vouchers:" in result.stdout
    assert "EVM Test Voucher" in result.stdout


def test_account_balance_error(mocker, env_files, mock_voucher_empty, mock_get_balances):
    """Test error handling in the account balance command when API returns an error."""
    settings.CONFIG_FILE = env_files[1]

    mock_client_class, mock_client = create_mock_client(None, None, mock_get_balances=mock_get_balances)

    mock_client.get_balances = AsyncMock(
        side_effect=Exception(
            "Failed to retrieve balance for address 0xCAfEcAfeCAfECaFeCaFecaFecaFECafECafeCaFe. Status code: 404"
        )
    )
    mock_client.voucher = mock_voucher_empty

    mocker.patch("aleph_client.commands.account.AlephHttpClient", mock_client_class)

    # Test with an address directly
    result = runner.invoke(
        app, ["account", "balance", "--address", "0xCAfEcAfeCAfECaFeCaFecaFecaFECafECafeCaFe", "--chain", "ETH"]
    )

    # The command should run without crashing but report the error
    assert result.exit_code == 0
    assert "Failed to retrieve balance for address" in result.stdout


def test_account_vouchers_display(mocker, env_files, mock_voucher_service):
    """Test that vouchers are properly displayed in the account vouchers command."""
    settings.CONFIG_FILE = env_files[1]

    # Mock the HTTP client
    mock_client = mocker.AsyncMock()
    mock_client.voucher = mock_voucher_service
    mocker.patch("aleph_client.commands.account.AlephHttpClient.__aenter__", return_value=mock_client)

    # Create a test address
    test_address = "0xCAfEcAfeCAfECaFeCaFecaFecaFECafECafeCaFe"

    # Test the command
    result = runner.invoke(app, ["account", "vouchers", "--address", test_address, "--chain", "ETH"])

    # Check that the command executed successfully
    assert result.exit_code == 0

    # Verify voucher service was called with the correct address
    mock_voucher_service.get_vouchers.assert_called_once_with(address=test_address)

    # Check that the voucher information is displayed in the output
    assert "Vouchers" in result.stdout
    assert "EVM Test Voucher" in result.stdout
    assert "Solana Test Voucher" in result.stdout
    assert "Duration: 30 days" in result.stdout
    assert "Duration: 60 days" in result.stdout
    assert "Compute Units: 4" in result.stdout
    assert "Compute Units: 8" in result.stdout

    # Test with private key file instead of address
    result = runner.invoke(app, ["account", "vouchers", "--private-key-file", str(env_files[0]), "--chain", "ETH"])

    # Check that the command executed successfully
    assert result.exit_code == 0

    # The mock should be called again, but with the address from the account loaded from the key file
    assert mock_voucher_service.get_vouchers.call_count == 2


def test_account_vouchers_no_vouchers(mocker, env_files):
    """Test the account vouchers command when no vouchers are available."""
    settings.CONFIG_FILE = env_files[1]

    # Create a mock voucher service that returns an empty list
    mock_voucher_service = mocker.MagicMock()
    mock_voucher_service.get_vouchers = mocker.AsyncMock(return_value=[])

    # Mock the HTTP client
    mock_client = mocker.AsyncMock()
    mock_client.voucher = mock_voucher_service
    mocker.patch("aleph_client.commands.account.AlephHttpClient.__aenter__", return_value=mock_client)

    # Create a test address
    test_address = "0xCAfEcAfeCAfECaFeCaFecaFecaFECafECafeCaFe"

    # Test the command
    result = runner.invoke(app, ["account", "vouchers", "--address", test_address, "--chain", "ETH"])

    # Check that the command executed successfully
    assert result.exit_code == 0

    # Check that the "no vouchers" message is displayed
    assert "No vouchers found for this address" in result.stdout


def test_account_config(env_files):
    with patch("aleph_client.commands.account.save_main_configuration") as mock_save_config:
        # Make sure the config can be saved
        mock_save_config.return_value = None

        settings.CONFIG_FILE = env_files[1]
        result = runner.invoke(
            app, ["account", "config", "--private-key-file", str(env_files[0]), "--chain", "ETH", "--non-it"]
        )
        assert result.exit_code == 0


@patch("aleph.sdk.wallets.ledger.ethereum.LedgerETHAccount.get_accounts")
def test_account_config_with_ledger(mock_get_accounts):
    """Test configuring account with a Ledger device."""
    # Create mock Ledger accounts
    mock_account1 = MagicMock()
    mock_account1.address = "0xdeadbeef1234567890123456789012345678beef"
    mock_account2 = MagicMock()
    mock_account2.address = "0xcafebabe5678901234567890123456789012cafe"
    mock_get_accounts.return_value = [mock_account1, mock_account2]

    # Create a temporary config file
    with runner.isolated_filesystem():
        config_dir = Path("test_config")
        config_dir.mkdir()
        config_file = config_dir / "config.json"

        with (
            patch("aleph.sdk.conf.settings.CONFIG_FILE", config_file),
            patch("aleph.sdk.conf.settings.CONFIG_HOME", str(config_dir)),
            patch("aleph_client.commands.account.Prompt.ask", return_value="1"),
            patch("aleph_client.commands.account.yes_no_input", return_value=True),
            patch("aleph_client.commands.account.save_main_configuration"),
            patch("aleph_client.utils.list_unlinked_keys", return_value=([], None)),
        ):
            # Use --no to skip interactive mode
            result = runner.invoke(
                app,
                [
                    "account",
                    "config",
                    "--account-type",
                    "hardware",
                    "--chain",
                    "ETH",
                    "--address",
                    "0xdeadbeef1234567890123456789012345678beef",
                    "--non-it",
                ],
            )

            assert result.exit_code == 0


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


def test_message_get_with_reject(mocker, store_message_fixture):
    message = StoreMessage.model_validate(store_message_fixture)
    mocker.patch("aleph.sdk.AlephHttpClient.get_message", return_value=[message, "rejected"])
    mocker.patch(
        "aleph.sdk.AlephHttpClient.get_message_error",
        return_value={
            "error_code": 100,
            "details": {"errors": ["File not found: Could not retrieve file from storage at this time"]},
        },
    )
    result = runner.invoke(
        app,
        [
            "message",
            "get",
            FAKE_STORE_HASH,
        ],
    )
    assert result.exit_code == 0
    assert "Message Status: rejected" in result.stdout


def test_message_get_with_forgotten(mocker):
    """Test the behavior when a message has been forgotten."""
    # Mock the get_message method to raise ForgottenMessageError
    mocker.patch(
        "aleph.sdk.AlephHttpClient.get_message",
        side_effect=ForgottenMessageError(
            f"The requested message {FAKE_STORE_HASH} has been forgotten by node1, node2"
        ),
    )

    result = runner.invoke(
        app,
        [
            "message",
            "get",
            FAKE_STORE_HASH,
        ],
    )

    # Verify output matches expected response for forgotten messages
    assert result.exit_code == 0
    assert "Message has been forgotten on aleph.cloud" in result.stdout


def test_message_get_not_found(mocker):
    """Test the behavior when a message is not found."""
    # Mock the get_message method to raise MessageNotFoundError
    mocker.patch(
        "aleph.sdk.AlephHttpClient.get_message", side_effect=MessageNotFoundError(f"No such hash {FAKE_STORE_HASH}")
    )

    result = runner.invoke(
        app,
        [
            "message",
            "get",
            FAKE_STORE_HASH,
        ],
    )

    # Verify output matches expected response for not found messages
    assert result.exit_code == 0
    assert "Message does not exist on aleph.cloud" in result.stdout


def test_message_get_removed(mocker):
    """Test the behavior when a message has been removed."""
    # Mock the get_message method to raise RemovedMessageError
    mocker.patch(
        "aleph.sdk.AlephHttpClient.get_message",
        side_effect=RemovedMessageError(f"The requested message {FAKE_STORE_HASH} has been removed by admin"),
    )

    result = runner.invoke(
        app,
        [
            "message",
            "get",
            FAKE_STORE_HASH,
        ],
    )

    # Verify output matches expected response for removed messages
    assert result.exit_code == 0
    assert "Message has been removed on aleph.cloud" in result.stdout


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


@pytest.mark.asyncio
async def test_file_upload(mock_authenticated_aleph_http_client, capsys):
    with NamedTemporaryFile() as tmp:
        content = b"Test pyaleph upload\n"
        expected_hash = hashlib.sha256(content).hexdigest()
        tmp.write(content)
        tmp.flush()

        await upload(Path(tmp.name))
        result = capsys.readouterr().out

        assert result is not None
        assert expected_hash in result


@pytest.mark.asyncio
async def test_file_upload_storage_engine(mock_authenticated_aleph_http_client, capsys, monkeypatch):
    """
    Test Storage selections to ensure :
        - Small file can be published over ipfs / storage engine
        - File larger than 4MB got redirected to IPFS
    """
    with NamedTemporaryFile() as tmp:
        content = b"Test storage engine selection\n"
        tmp.write(content)
        tmp.flush()

        # Track what storage_engine was passed to create_store
        original_create_store = mock_authenticated_aleph_http_client.return_value.__aenter__.return_value.create_store
        storage_used = None

        async def create_store_tracker(*args, **kwargs):
            nonlocal storage_used
            storage_used = kwargs.get("storage_engine")
            return await original_create_store(*args, **kwargs)

        mock_authenticated_aleph_http_client.return_value.__aenter__.return_value.create_store = AsyncMock(
            side_effect=create_store_tracker
        )

        # Test explicit IPFS storage for small file
        await upload(Path(tmp.name), storage_engine=StorageEnum.ipfs)
        assert storage_used == StorageEnum.ipfs

        # Test default storage engine for small file (should be storage)
        storage_used = None
        await upload(Path(tmp.name))
        assert storage_used == StorageEnum.storage

        # Test with large file that exceeds 4MB limit
        with patch("builtins.open") as mock_open:
            # Mock file content to be larger than 4MB
            mock_large_content = b"X" * (4 * 1024 * 1024 + 100)  # 4MB + 100 bytes
            mock_file = MagicMock()
            mock_file.read.return_value = mock_large_content
            mock_open.return_value.__enter__.return_value = mock_file

            # Test default behavior with large file (should use IPFS)
            storage_used = None
            await upload(Path(tmp.name))
            assert storage_used == StorageEnum.ipfs

            # Test with explicit storage override that gets changed to IPFS
            storage_used = None
            with patch("typer.echo") as mock_echo:
                await upload(Path(tmp.name), storage_engine=StorageEnum.storage)
                # The warning should be the first echo call
                mock_echo.assert_any_call("Warning: File is larger than 4MB, switching to IPFS storage.")
                assert storage_used == StorageEnum.ipfs


def test_file_download(mock_aleph_http_client, tmp_path):
    """Test downloading a file from the Aleph network.

    This test uses proper mocking of the AlephHttpClient to simulate downloading
    """

    ipfs_cid = "QmeomffUNfmQy76CQGy9NdmqEnnHU9soCexBnGU3ezPHVH"
    test_content = b"Test file content"

    output_dir = tmp_path / "download_test"
    output_dir.mkdir(parents=True, exist_ok=True)

    async def mock_download_to_buffer(_, file_obj, *args, **kwargs):
        file_obj.write(test_content)
        return len(test_content)

    mock_client = mock_aleph_http_client.return_value.__aenter__.return_value
    mock_client.download_file_to_buffer.side_effect = mock_download_to_buffer
    mock_client.download_file_ipfs_to_buffer.side_effect = mock_download_to_buffer

    with patch("aleph_client.commands.files.logger.info") as mock_info:
        result = runner.invoke(
            app,
            [
                "file",
                "download",
                ipfs_cid,
                "--output-path",
                str(output_dir),
            ],
        )

        assert result.exit_code == 0

        # Verify the logging was called with the expected message
        mock_info.assert_called_with(f"Downloading {ipfs_cid} ...")

    output_file = output_dir / ipfs_cid
    assert output_file.exists(), f"Output file {output_file} does not exist"

    with open(output_file, "rb") as f:
        content = f.read()
        assert content == test_content

    mock_client.download_file_to_buffer.assert_called_once()

    output_file.unlink()
    output_dir.rmdir()


def test_file_download_ipfs(mock_aleph_http_client, tmp_path):
    """Test downloading a file from the Aleph network using IPFS method.

    This test verifies the IPFS download path works correctly.
    """
    # Test file hash/CID to download
    ipfs_cid = "QmeomffUNfmQy76CQGy9NdmqEnnHU9soCexBnGU3ezPHVH"
    test_content = b"Test IPFS file content"

    # Set up a test directory for the downloaded file
    output_dir = tmp_path / "ipfs_download_test"
    output_dir.mkdir(parents=True, exist_ok=True)

    async def mock_download_to_buffer(_, file_obj, *args, **kwargs):
        file_obj.write(test_content)
        return len(test_content)

    # Set up the client mock methods
    mock_client = mock_aleph_http_client.return_value.__aenter__.return_value
    mock_client.download_file_to_buffer.side_effect = mock_download_to_buffer
    mock_client.download_file_ipfs_to_buffer.side_effect = mock_download_to_buffer

    # Run the CLI command with IPFS flag
    result = runner.invoke(
        app,
        [
            "file",
            "download",
            ipfs_cid,
            "--use-ipfs",
            "--output-path",
            str(output_dir),
        ],
    )

    assert result.exit_code == 0

    output_file = output_dir / ipfs_cid
    assert output_file.exists(), f"Output file {output_file} does not exist"

    with open(output_file, "rb") as f:
        content = f.read()
        assert content == test_content, f"File content does not match. Expected {test_content!r}, got {content!r}"

    mock_client.download_file_ipfs_to_buffer.assert_called_once()
    mock_client.download_file_to_buffer.assert_not_called()

    output_file.unlink()
    output_dir.rmdir()


def test_file_download_only_info(mock_aleph_http_client):
    """Test retrieving only file information without downloading the file."""

    stored_content = StoredContent(
        hash=FAKE_STORE_HASH,
        filename=f"{FAKE_STORE_HASH}.txt",
        url=f"https://api.aleph.im/storage/{FAKE_STORE_HASH}",
    )
    mock_aleph_http_client.return_value.__aenter__.return_value.get_stored_content.return_value = stored_content

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
    assert FAKE_STORE_HASH in result.return_value.hash


def test_file_list(mock_aiohttp_client_session):
    result = runner.invoke(
        app,
        [
            "file",
            "list",
            "--address",
            "0xe0aaF578B287de16852dbc54Ae34a263FF2F4b9E",
        ],
    )

    assert result.exit_code == 0
    assert "Address:" in result.stdout

    assert "0dd9bb810b7a31cc50c8ad1e6569905" in result.stdout


def test_file_list_error(mocker):
    """Test error handling in the file list command when API returns an error."""
    # Create a mock response with error status
    mock_response = AsyncMock()
    mock_response.status = 404

    # Create a mock session that returns our error response
    mock_session = AsyncMock()
    mock_session.__aenter__.return_value = mock_session
    mock_session.get.return_value = mock_response

    # Patch aiohttp.ClientSession to return our mock
    with patch("aiohttp.ClientSession", return_value=mock_session):
        result = runner.invoke(
            app,
            [
                "file",
                "list",
                "--address",
                "0xe0aaF578B287de16852dbc54Ae34a263FF2F4b9E",
            ],
        )

    # The command should run without crashing but report the error
    assert result.exit_code == 0
    assert "Failed to retrieve files for address" in result.stdout
    assert "Status code: 404" in result.stdout
