from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from aiohttp import ClientResponseError

from aleph_client.commands.credit import history, show


@pytest.fixture
def mock_credit_balance_response():
    """Create a mock response for credit balance API call."""
    mock_response = AsyncMock()
    mock_response.__aenter__.return_value = mock_response
    mock_response.status = 200
    mock_response.json = AsyncMock(
        return_value={
            "address": "0x1234567890123456789012345678901234567890",
            "balance": 24853,
            "locked_amount": 4663.33,
            "credit_balance": 1000000000,
            "details": {"AVAX": 4000, "BASE": 10000, "ETH": 10853},
        }
    )
    return mock_response


@pytest.fixture
def mock_credit_history_response():
    """Create a mock response for credit history API call."""
    mock_response = AsyncMock()
    mock_response.__aenter__.return_value = mock_response
    mock_response.status = 200
    mock_response.json = AsyncMock(
        return_value={
            "address": "0x1234567890123456789012345678901234567890",
            "credit_history": [
                {
                    "amount": 1000000000,
                    "message_timestamp": "2023-06-15T12:30:45Z",
                    "payment_method": "credit_card",
                    "origin": "purchase",
                    "origin_ref": "txn_123456",
                    "expiration_date": "2024-06-15T12:30:45Z",
                    "credit_ref": "credit_ref_1",
                    "credit_index": 1,
                },
                {
                    "amount": 500000000,
                    "message_timestamp": "2023-07-20T15:45:30Z",
                    "payment_method": "wire_transfer",
                    "origin": "purchase",
                    "origin_ref": "txn_789012",
                    "expiration_date": None,
                    "credit_ref": "credit_ref_2",
                    "credit_index": 2,
                },
            ],
            "pagination_page": 1,
            "pagination_total": 1,
            "pagination_per_page": 100,
            "pagination_total_items": 2,
            "pagination_item": "credit_history",
        }
    )
    return mock_response


@pytest.fixture
def mock_credit_error_response():
    """Create a mock error response for credit API calls."""
    mock_response = AsyncMock()
    mock_response.__aenter__.return_value = mock_response
    mock_response.status = 404
    mock_response.json = AsyncMock(
        side_effect=ClientResponseError(request_info=AsyncMock(), history=AsyncMock(), status=404, message="Not Found")
    )
    return mock_response


@pytest.mark.asyncio
async def test_show_command(mock_credit_balance_response, capsys):
    """Test the show command with an explicit address."""

    @patch("aiohttp.ClientSession.get")
    async def run(mock_get):
        mock_get.return_value = mock_credit_balance_response

        # Run the show command with an explicit address
        await show(
            address="0x1234567890123456789012345678901234567890",
            private_key=None,
            private_key_file=None,
            json=False,
            debug=False,
        )

    await run()
    captured = capsys.readouterr()
    assert "Credits Infos" in captured.out
    assert "0x1234567890123456789012345678901234567890" in captured.out
    # The credits might be displayed in their raw form without formatting
    assert "1000000000" in captured.out


@pytest.mark.asyncio
async def test_show_json_output(mock_credit_balance_response, capsys):
    """Test the show command with JSON output."""
    import json

    @patch("aiohttp.ClientSession.get")
    async def run(mock_get):
        mock_get.return_value = mock_credit_balance_response

        # Run the show command with JSON output
        await show(
            address="0x1234567890123456789012345678901234567890",
            private_key=None,
            private_key_file=None,
            json=True,
            debug=False,
        )

    await run()
    captured = capsys.readouterr()

    # Try to parse the output as JSON to validate it's properly formatted
    parsed_json = json.loads(captured.out)
    # Verify expected data is in the parsed JSON
    assert parsed_json["address"] == "0x1234567890123456789012345678901234567890"
    assert parsed_json["credit_balance"] == 1000000000


@pytest.mark.asyncio
async def test_show_with_account(mock_credit_balance_response):
    """Test the show command using account-derived address."""

    @patch("aiohttp.ClientSession.get")
    @patch("aleph_client.commands.credit._load_account")
    async def run(mock_load_account, mock_get):
        mock_get.return_value = mock_credit_balance_response

        # Setup mock account that returns a specific address
        mock_account = AsyncMock()
        mock_account.get_address.return_value = "0x1234567890123456789012345678901234567890"
        mock_load_account.return_value = mock_account

        # Run the show command without explicit address (should use account address)
        await show(
            address="",
            private_key="dummy_private_key",
            private_key_file=None,
            json=False,
            debug=False,
        )

        # Verify the account was loaded and its address used
        mock_load_account.assert_called_once()
        mock_account.get_address.assert_called_once()

    await run()


@pytest.mark.asyncio
async def test_show_no_address_no_account(capsys):
    """Test the show command with no address and no account."""

    @patch("aleph_client.commands.credit._load_account")
    async def run(mock_load_account):
        # Setup the mock account to return None (no account found)
        mock_load_account.return_value = None

        # Run the show command without address and without account
        await show(
            address="",
            private_key=None,
            private_key_file=None,
            json=False,
            debug=False,
        )

    await run()
    captured = capsys.readouterr()
    assert "Error: Please provide either a private key, private key file, or an address." in captured.out


@pytest.mark.asyncio
async def test_show_api_error(mock_credit_error_response):
    """Test the show command handling API errors."""

    @patch("aiohttp.ClientSession.get")
    async def run(mock_get):
        mock_get.return_value = mock_credit_error_response

        # Run the show command and expect an exception
        with pytest.raises(ClientResponseError):
            await show(
                address="0x1234567890123456789012345678901234567890",
                private_key=None,
                private_key_file=None,
                json=False,
                debug=False,
            )

    await run()


@pytest.mark.asyncio
async def test_history_command(mock_credit_history_response, capsys):
    """Test the history command with an explicit address."""

    @patch("aiohttp.ClientSession.get")
    async def run(mock_get):
        mock_get.return_value = mock_credit_history_response

        # Run the history command with an explicit address
        await history(
            address="0x1234567890123456789012345678901234567890",
            private_key=None,
            private_key_file=None,
            page_size=100,
            page=1,
            json=False,
            debug=False,
        )

    await run()
    captured = capsys.readouterr()
    assert "Credits History" in captured.out
    assert "0x1234567890123456789012345678901234567890" in captured.out
    assert "credit_card" in captured.out
    assert "Page: 1" in captured.out


@pytest.mark.asyncio
async def test_history_json_output(mock_credit_history_response, capsys):
    """Test the history command with JSON output."""
    import json

    @patch("aiohttp.ClientSession.get")
    async def run(mock_get):
        mock_get.return_value = mock_credit_history_response

        # Run the history command with JSON output
        await history(
            address="0x1234567890123456789012345678901234567890",
            private_key=None,
            private_key_file=None,
            page_size=100,
            page=1,
            json=True,
            debug=False,
        )

    await run()
    captured = capsys.readouterr()

    # Try to parse the output as JSON to validate it's properly formatted
    parsed_json = json.loads(captured.out)

    # Verify expected data is in the parsed JSON
    assert parsed_json["address"] == "0x1234567890123456789012345678901234567890"
    assert parsed_json["credit_history"][0]["amount"] == 1000000000
    assert parsed_json["credit_history"][0]["payment_method"] == "credit_card"
    assert len(parsed_json["credit_history"]) == 2


@pytest.mark.asyncio
async def test_history_api_error(mock_credit_error_response):
    """Test the history command handling API errors."""

    @patch("aiohttp.ClientSession.get")
    async def run(mock_get):
        mock_get.return_value = mock_credit_error_response

        # Run the history command and expect an exception
        with pytest.raises(ClientResponseError):
            await history(
                address="0x1234567890123456789012345678901234567890",
                private_key=None,
                private_key_file=None,
                page_size=100,
                page=1,
                json=False,
                debug=False,
            )

    await run()
