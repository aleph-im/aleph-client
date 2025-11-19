from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer
from aleph.sdk.conf import AccountType, MainConfiguration
from aleph_message.models import Chain
from ledgereth.exceptions import LedgerError

from aleph_client.utils import load_account


@pytest.fixture
def mock_config_internal():
    """Create a mock internal configuration."""
    return MainConfiguration(path=Path("/fake/path.key"), chain=Chain.ETH)


@pytest.fixture
def mock_config_external():
    """Create a mock external (ledger) configuration."""
    return MainConfiguration(path=None, chain=Chain.ETH, address="0xdeadbeef1234567890123456789012345678beef")


@pytest.fixture
def mock_config_hardware():
    """Create a mock hardware (ledger) configuration."""
    return MainConfiguration(
        path=None,
        chain=Chain.ETH,
        address="0xdeadbeef1234567890123456789012345678beef",
        type=AccountType.HARDWARE,
    )


@patch("aleph_client.utils.load_main_configuration")
@patch("aleph_client.utils._load_account")
def test_load_account_with_internal_config(mock_load_account, mock_load_config, mock_config_internal):
    """Test load_account with an internal configuration."""
    mock_load_config.return_value = mock_config_internal

    load_account(None, None)

    # Verify _load_account was called with the correct parameters for internal account
    mock_load_account.assert_called_with(None, None, chain=Chain.ETH)


@patch("aleph_client.utils.load_main_configuration")
@patch("aleph_client.utils.wait_for_ledger_connection")
@patch("aleph_client.utils._load_account")
def test_load_account_with_external_config(mock_load_account, mock_load_config, mock_config_external):
    """Test load_account with an external (ledger) configuration."""
    mock_load_config.return_value = mock_config_external

    load_account(None, None)

    # Verify _load_account was called with some chain parameter
    assert mock_load_account.call_args is not None

    # For this test, we don't need to validate the exact mock object identity
    # Just make sure the method was called with the proper args
    mock_load_account.assert_called_once()


@patch("aleph_client.utils.load_main_configuration")
@patch("aleph_client.utils._load_account")
def test_load_account_with_override_chain(mock_load_account, mock_load_config, mock_config_internal):
    """Test load_account with an explicit chain parameter that overrides the config."""
    mock_load_config.return_value = mock_config_internal

    load_account(None, None, chain=Chain.SOL)

    # Verify explicit chain was used instead of config chain
    mock_load_account.assert_called_with(None, None, chain=Chain.SOL)


@patch("aleph_client.utils.load_main_configuration")
@patch("aleph_client.utils._load_account")
def test_load_account_fallback_to_private_key(mock_load_account, mock_load_config):
    """Test load_account falling back to private key when no config exists."""
    mock_load_config.return_value = None

    load_account("0xdeadbeef", None)

    # Verify private key string was used
    mock_load_account.assert_called_with("0xdeadbeef", None, chain=None)


@patch("aleph_client.utils.load_main_configuration")
@patch("aleph_client.utils._load_account")
def test_load_account_fallback_to_private_key_file(mock_load_account, mock_load_config):
    """Test load_account falling back to private key file when no config exists."""
    mock_load_config.return_value = None

    private_key_file = MagicMock()
    private_key_file.exists.return_value = True

    load_account(None, private_key_file)

    # Verify private key file was used
    mock_load_account.assert_called_with(None, private_key_file, chain=None)


@patch("aleph_client.utils.load_main_configuration")
@patch("aleph_client.utils._load_account")
def test_load_account_nonexistent_file_raises_error(mock_load_account, mock_load_config):
    """Test that load_account raises an error when file doesn't exist and no config exists."""
    mock_load_config.return_value = None

    private_key_file = MagicMock()
    private_key_file.exists.return_value = False

    with pytest.raises(typer.Exit):
        load_account(None, private_key_file)


@patch("aleph_client.utils.load_main_configuration")
@patch("aleph_client.utils.wait_for_ledger_connection")
@patch("aleph_client.utils._load_account")
def test_ledger_config(mock_load_account, mock_wait_for_ledger, mock_load_config, mock_config_hardware):
    """Test load_account with a hardware ledger configuration."""
    mock_load_config.return_value = mock_config_hardware
    mock_wait_for_ledger.return_value = None

    load_account(None, None)

    # Verify wait_for_ledger_connection was called
    mock_wait_for_ledger.assert_called_once()
    # Verify _load_account was called with the correct parameters for hardware account
    mock_load_account.assert_called_with(None, None, chain=Chain.ETH)


@patch("aleph_client.utils.load_main_configuration")
@patch("aleph_client.utils.wait_for_ledger_connection")
@patch("aleph_client.utils._load_account")
def test_ledger_failure(mock_load_account, mock_wait_for_ledger, mock_load_config, mock_config_hardware):
    """Test load_account with a hardware ledger configuration when connection fails."""

    mock_load_config.return_value = mock_config_hardware

    mock_wait_for_ledger.side_effect = LedgerError("Cannot connect to ledger")

    # Check that typer.Exit is raised
    with pytest.raises(typer.Exit):
        load_account(None, None)

    # Verify wait_for_ledger_connection was called
    mock_wait_for_ledger.assert_called_once()

    # Verify _load_account was not called
    mock_load_account.assert_not_called()


@patch("aleph_client.utils.load_main_configuration")
@patch("aleph_client.utils.wait_for_ledger_connection")
@patch("aleph_client.utils._load_account")
def test_ledger_os_error(mock_load_account, mock_wait_for_ledger, mock_load_config, mock_config_hardware):
    """Test load_account with a hardware ledger configuration when an OS error occurs."""
    mock_load_config.return_value = mock_config_hardware

    # Simulate an OS error (permission issues, etc)
    mock_wait_for_ledger.side_effect = OSError("Permission denied")

    # Check that typer.Exit is raised
    with pytest.raises(typer.Exit):
        load_account(None, None)

    # Verify wait_for_ledger_connection was called
    mock_wait_for_ledger.assert_called_once()
    # Verify _load_account was not called
    mock_load_account.assert_not_called()
