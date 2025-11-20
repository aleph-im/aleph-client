from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer
from aleph.sdk.conf import AccountType, MainConfiguration
from aleph_message.models import Chain
from ledgereth.exceptions import LedgerError

from aleph_client.utils import (
    get_first_ledger_name,
    list_ledger_dongles,
    load_account,
    wait_for_ledger_connection,
)

PATCH_LEDGER_ACCOUNTS = "aleph.sdk.wallets.ledger.ethereum.LedgerETHAccount.get_accounts"
PATCH_HID_ENUM = "hid.enumerate"
PATCH_SLEEP = "time.sleep"
PATCH_WAIT_LEDGER = "aleph_client.utils.wait_for_ledger_connection"
PATCH_LOAD_CONFIG = "aleph_client.utils.load_main_configuration"
PATCH_LOAD_ACCOUNT_INTERNAL = "aleph_client.utils._load_account"


@pytest.fixture
def mock_get_accounts():
    with patch(PATCH_LEDGER_ACCOUNTS) as p:
        yield p


@pytest.fixture
def mock_hid_enum():
    with patch(PATCH_HID_ENUM) as p:
        yield p


@pytest.fixture
def no_sleep():
    with patch(PATCH_SLEEP):
        yield


@pytest.fixture
def mock_ledger_config():
    """Create a mock ledger hardware wallet configuration."""
    return MainConfiguration(
        path=None,
        chain=Chain.ETH,
        address="0xdeadbeef1234567890123456789012345678beef",
        type=AccountType.HARDWARE,
    )


@pytest.fixture
def mock_ledger_config_with_path():
    """Create a mock ledger hardware wallet configuration with derivation path."""
    return MainConfiguration(
        path=None,
        chain=Chain.ETH,
        address="0xdeadbeef1234567890123456789012345678beef",
        type=AccountType.HARDWARE,
        derivation_path="44'/60'/0'/0/0",
    )


@pytest.fixture
def mock_imported_config():
    """Create a mock imported wallet configuration."""
    return MainConfiguration(
        path=Path("/home/user/.aleph/private-keys/test.key"),
        chain=Chain.ETH,
        address=None,
        type=AccountType.IMPORTED,
    )


@pytest.fixture
def mock_ledger_accounts():
    """Create mock ledger accounts."""
    mock_account1 = MagicMock()
    mock_account1.address = "0xdeadbeef1234567890123456789012345678beef"
    mock_account1.get_address = MagicMock(return_value=mock_account1.address)
    mock_account2 = MagicMock()
    mock_account2.address = "0xcafebabe5678901234567890123456789012cafe"
    mock_account2.get_address = MagicMock(return_value=mock_account2.address)
    return [mock_account1, mock_account2]


def test_load_account_with_ledger(mock_get_accounts, mock_ledger_config, mock_ledger_accounts):
    mock_get_accounts.return_value = mock_ledger_accounts

    with (
        patch(PATCH_LOAD_CONFIG, return_value=mock_ledger_config),
        patch(PATCH_LOAD_ACCOUNT_INTERNAL, return_value=mock_ledger_accounts[0]),
        patch(PATCH_WAIT_LEDGER),
    ):
        account = load_account(None, None)

    assert account.get_address() == mock_ledger_accounts[0].address


@patch("aleph.sdk.wallets.ledger.ethereum.LedgerETHAccount.get_accounts")
def test_list_ledger_dongles(mock_get_accounts, mock_ledger_accounts):
    """Test listing Ledger devices."""
    mock_get_accounts.return_value = mock_ledger_accounts

    with patch("hid.enumerate") as mock_enumerate:
        # Set up mock HID devices
        mock_enumerate.return_value = [
            {
                "vendor_id": 0x2C97,
                "product_id": 0x0001,
                "path": b"usb-123",
                "product_string": "Ledger Nano X",
                "serial_number": "1234567890",
            },
            {
                "vendor_id": 0x2C97,
                "product_id": 0x0001,
                "path": b"usb-123:1.0",
                "product_string": "Ledger Nano X",
                "serial_number": "1234567890",
            },
            {
                "vendor_id": 0x2C97,
                "product_id": 0x0002,
                "path": b"usb-456",
                "product_string": "Ledger Nano S",
                "serial_number": "0987654321",
            },
            {
                "vendor_id": 0x1234,  # Non-Ledger device
                "product_id": 0x5678,
                "path": b"usb-789",
                "product_string": "Not a Ledger",
                "serial_number": "11223344",
            },
        ]

        # Test with unique_only=True (default)
        dongles = list_ledger_dongles()
        assert len(dongles) == 2  # Should filter out duplicates and non-Ledger devices
        assert dongles[0]["product_string"] == "Ledger Nano X"
        assert dongles[1]["product_string"] == "Ledger Nano S"

        # Test with unique_only=False
        dongles = list_ledger_dongles(unique_only=False)
        assert len(dongles) == 3  # Should include duplicates but not non-Ledger devices


@patch("aleph.sdk.wallets.ledger.ethereum.LedgerETHAccount.get_accounts")
def test_get_first_ledger_name(mock_get_accounts, mock_ledger_accounts):
    """Test getting the name of the first connected Ledger device."""
    mock_get_accounts.return_value = mock_ledger_accounts

    with patch("aleph_client.utils.list_ledger_dongles") as mock_list_dongles:
        # Test with a connected device
        mock_list_dongles.return_value = [
            {
                "path": b"usb-123",
                "product_string": "Ledger Nano X",
            }
        ]
        name = get_first_ledger_name()
        assert name == "Ledger Nano X (usb-123)"

        # Test with no connected devices
        mock_list_dongles.return_value = []
        name = get_first_ledger_name()
        assert name == "No Ledger found"


def test_wait_for_ledger_already_connected(mock_get_accounts, mock_hid_enum, no_sleep):
    """
    Ledger already connected & have eth app open

    :param mock_get_accounts:
    :param mock_hid_enum:
    :param no_sleep:
    :return:
    """
    mock_get_accounts.return_value = ["0xabc"]

    wait_for_ledger_connection()

    mock_get_accounts.assert_called_once()
    mock_hid_enum.assert_not_called()


def test_wait_for_ledger_device_appears(mock_get_accounts, mock_hid_enum, no_sleep):
    """
    No device detected -> continue loop -> device appears -> success

    :param mock_get_accounts:
    :param mock_hid_enum:
    :param no_sleep:
    :return:
    """
    mock_get_accounts.side_effect = [
        Exception("not ready"),  # top-level
        Exception("still no"),  # first loop
        ["0xabc"],  # second loop -> success
    ]

    mock_hid_enum.side_effect = [
        [],  # first iteration -> no device
        [{}],  # second iteration -> device present
        [{}],  # third iteration (just in case)
    ]

    wait_for_ledger_connection()

    assert mock_get_accounts.call_count == 3


def test_wait_for_ledger_locked_then_ready(mock_get_accounts, mock_hid_enum, no_sleep):
    """
     Ledger locked -> LedgerError -> retry -> success

    :param mock_get_accounts:
    :param mock_hid_enum:
    :param no_sleep:
    :return:
    """
    mock_get_accounts.side_effect = [
        Exception("not ready"),  # top-level
        LedgerError("locked"),  # first loop
        ["0xabc"],  # next loop -> success
    ]

    mock_hid_enum.return_value = [{"id": 1}]  # device always present

    wait_for_ledger_connection()

    assert mock_get_accounts.call_count == 3


def test_wait_for_ledger_comm_error_then_ready(mock_get_accounts, mock_hid_enum, no_sleep):
    """
    Generic communication error -> retry -> success

    :param mock_get_accounts:
    :param mock_hid_enum:
    :param no_sleep:
    :return:
    """
    mock_get_accounts.side_effect = [
        Exception("top-level fail"),
        Exception("comm error"),
        ["0xabc"],
    ]

    mock_hid_enum.return_value = [{"id": 1}]

    wait_for_ledger_connection()

    assert mock_get_accounts.call_count == 3


def test_wait_for_ledger_oserror(mock_get_accounts, mock_hid_enum, no_sleep):
    """
    OS error from hid.enumerate -> should exit via typer.Exit(1)
    :param mock_get_accounts:
    :param mock_hid_enum:
    :param no_sleep:
    :return:
    """
    mock_get_accounts.side_effect = Exception("not ready")
    mock_hid_enum.side_effect = OSError("permission denied")

    with pytest.raises(typer.Exit) as exc:
        wait_for_ledger_connection()

    assert exc.value.exit_code == 1


def test_wait_for_ledger_keyboard_interrupt(mock_get_accounts, mock_hid_enum, no_sleep):
    """
    KeyboardInterrupt raised inside loop -> should exit via typer.Exit(1)

    :param mock_get_accounts:
    :param mock_hid_enum:
    :param no_sleep:
    :return:
    """
    mock_get_accounts.side_effect = Exception("not ready")
    mock_hid_enum.side_effect = KeyboardInterrupt

    with pytest.raises(typer.Exit) as exc:
        wait_for_ledger_connection()

    assert exc.value.exit_code == 1


def test_wait_for_ledger_locked_once_then_ready(mock_get_accounts, mock_hid_enum, no_sleep):
    """
    Device present immediately, but first get_accounts raises LedgerError
    (wrong app), then success next iteration


    :param mock_get_accounts:
    :param mock_hid_enum:
    :param no_sleep:
    :return:
    """
    mock_get_accounts.side_effect = [
        Exception("not ready"),  # top-level
        LedgerError("locked"),  # loop 1
        ["0xabc"],  # loop 2 -> success
    ]

    mock_hid_enum.return_value = [{"id": 1}]

    wait_for_ledger_connection()

    assert mock_get_accounts.call_count == 3
