"""Tests for the --no-format flag."""

import pytest
from aleph_message.status import MessageStatus
from typer.testing import CliRunner

from aleph.sdk.conf import settings
from aleph_client.__main__ import app
from aleph_client.commands.utils import (
    colorful_json,
    colorized_status,
    is_no_format,
    set_no_format,
)

runner = CliRunner()


@pytest.fixture(autouse=True)
def reset_no_format():
    """Reset no_format flag after each test."""
    yield
    set_no_format(False)


def test_set_no_format():
    """Test that set_no_format sets the global flag."""
    assert is_no_format() is False
    set_no_format(True)
    assert is_no_format() is True


def test_colorful_json_no_format():
    """Test that colorful_json returns raw text when no_format is set."""
    json_str = '{"key": "value"}'

    # With formatting (default) - should contain ANSI escape codes
    formatted = colorful_json(json_str)
    assert formatted != json_str  # Should contain highlighting

    # Without formatting
    set_no_format(True)
    plain = colorful_json(json_str)
    assert plain == json_str  # Should return raw text


def test_colorized_status_no_format():
    """Test that colorized_status returns plain text when no_format is set."""
    set_no_format(True)
    result = colorized_status(MessageStatus.PROCESSED)
    assert result == str(MessageStatus.PROCESSED)
    # Should not contain ANSI escape codes
    assert "\x1b[" not in result


def test_no_format_flag_on_help():
    """Test that --no-format flag appears in help output."""
    result = runner.invoke(app, ["--no-format", "--help"])
    assert result.exit_code == 0
    assert "--no-format" in result.stdout


def test_no_format_flag_with_account_path():
    """Test --no-format flag works with a simple command."""
    result = runner.invoke(app, ["--no-format", "account", "path"])
    assert result.exit_code == 0
    assert "Aleph Home directory:" in result.stdout
    # Output should not contain ANSI escape codes
    assert "\x1b[" not in result.stdout


def test_no_format_flag_with_account_chain(env_files):
    """Test --no-format strips colors from chain display."""
    settings.CONFIG_FILE = env_files[1]
    result = runner.invoke(app, ["--no-format", "account", "chain"])
    assert result.exit_code == 0
    assert "Active Chain:" in result.stdout
    # Should not contain ANSI escape codes
    assert "\x1b[" not in result.stdout


def test_no_format_flag_with_account_address(env_files):
    """Test --no-format strips colors from address display."""
    settings.CONFIG_FILE = env_files[1]
    result = runner.invoke(app, ["--no-format", "account", "address", "--private-key-file", str(env_files[0])])
    assert result.exit_code == 0
    # Should contain address text but no ANSI escape codes
    assert "Addresses for Active Account" in result.stdout
    assert "\x1b[" not in result.stdout


def test_no_format_flag_with_file_list(mock_aiohttp_client_session):
    """Test --no-format produces plain table output for file list."""
    result = runner.invoke(
        app,
        [
            "--no-format",
            "file",
            "list",
            "--address",
            "0xe0aaF578B287de16852dbc54Ae34a263FF2F4b9E",
        ],
    )
    assert result.exit_code == 0
    assert "Address:" in result.stdout
    # Should not contain ANSI escape codes
    assert "\x1b[" not in result.stdout
    # Table borders should not be present (no box characters)
    assert "┌" not in result.stdout
    assert "│" not in result.stdout
    assert "└" not in result.stdout
    assert "╭" not in result.stdout
    assert "╰" not in result.stdout


def test_no_format_flag_with_account_balance(mocker, env_files, mock_voucher_service, mock_get_balances):
    """Test --no-format strips formatting from balance display."""
    from .test_instance import create_mock_client

    settings.CONFIG_FILE = env_files[1]
    mock_client_class, mock_client = create_mock_client(None, None, mock_get_balances=mock_get_balances)
    mock_client.voucher = mock_voucher_service
    mocker.patch("aleph_client.commands.account.AlephHttpClient", mock_client_class)

    result = runner.invoke(
        app,
        [
            "--no-format",
            "account",
            "balance",
            "--address",
            "0xCAfEcAfeCAfECaFeCaFecaFecaFECafECafeCaFe",
            "--chain",
            "ETH",
        ],
    )
    assert result.exit_code == 0
    assert "Account Infos" in result.stdout
    # Should not contain ANSI escape codes
    assert "\x1b[" not in result.stdout
