from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from aiohttp import ClientResponseError

from aleph_client.commands.credit import list_credits, show


@pytest.fixture
def mock_credit_balance_response():
    """Create a mock response for credit balance API call."""
    mock_response = AsyncMock()
    mock_response.__aenter__.return_value = mock_response
    mock_response.status = 200
    mock_response.json = AsyncMock(
        return_value={
            "address": "0x1234567890123456789012345678901234567890",
            "credits": 1000000000,
        }
    )
    return mock_response


@pytest.fixture
def mock_credits_list_response():
    """Create a mock response for credits list API call."""
    mock_response = AsyncMock()
    mock_response.__aenter__.return_value = mock_response
    mock_response.status = 200
    mock_response.json = AsyncMock(
        return_value={
            "credit_balances": [
                {
                    "address": "0x1234567890123456789012345678901234567890",
                    "credits": 1000000000,
                },
                {
                    "address": "0x0987654321098765432109876543210987654321",
                    "credits": 500000000,
                },
            ],
            "pagination_page": 1,
            "pagination_total": 1,
            "pagination_per_page": 100,
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
    assert "0x1234567890123456789012345678901234567890" in captured.out
    assert "1000000000" in captured.out


@pytest.mark.asyncio
async def test_show_with_account(mock_credit_balance_response):
    """Test the show command using account-derived address."""

    @patch("aiohttp.ClientSession.get")
    @patch("aleph_client.commands.credits._load_account")
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

    @patch("aleph_client.commands.credits._load_account")
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
async def test_list_credits_default(mock_credits_list_response, capsys):
    """Test the list_credits command with default parameters."""

    @patch("aiohttp.ClientSession.get")
    async def run(mock_get):
        mock_get.return_value = mock_credits_list_response

        # Run the list_credits command with default parameters
        await list_credits(
            page_size=100,
            page=1,
            min_balance=None,
            json=False,
        )

    await run()
    captured = capsys.readouterr()
    assert "Credits Information" in captured.out
    assert "0x1234567890123456789012345678901234567890" in captured.out
    # The credits might be displayed in their raw form without formatting
    assert "1000000000" in captured.out


@pytest.mark.asyncio
async def test_list_credits_with_filter(mock_credits_list_response, capsys):
    """Test the list_credits command with min_balance filter."""

    @patch("aiohttp.ClientSession.get")
    async def run(mock_get):
        mock_get.return_value = mock_credits_list_response

        # Run the list_credits command with min_balance filter
        await list_credits(
            page_size=100,
            page=1,
            min_balance=1000000,  # 0.01 credits with 8 decimals
            json=False,
        )

    await run()
    captured = capsys.readouterr()
    assert "Credits Information" in captured.out


@pytest.mark.asyncio
async def test_list_credits_json_output(mock_credits_list_response, capsys):
    """Test the list_credits command with JSON output."""

    @patch("aiohttp.ClientSession.get")
    async def run(mock_get):
        mock_get.return_value = mock_credits_list_response

        # Run the list_credits command with JSON output
        await list_credits(
            page_size=100,
            page=1,
            min_balance=None,
            json=True,
        )

    await run()
    captured = capsys.readouterr()
    assert "credit_balances" in captured.out
    assert "pagination_page" in captured.out


@pytest.mark.asyncio
async def test_list_credits_custom_pagination(mock_credits_list_response):
    """Test the list_credits command with custom pagination parameters."""

    @patch("aiohttp.ClientSession.get")
    async def run(mock_get):
        mock_get.return_value = mock_credits_list_response

        # Run the list_credits command with custom pagination
        await list_credits(
            page_size=50,
            page=2,
            min_balance=None,
            json=False,
        )

        # Verify that the parameters were passed correctly
        # In the SDK, these parameters are passed as part of the 'params' argument, not in the URL
        called_params = mock_get.call_args[1]["params"]
        assert called_params["pagination"] == "50"
        assert called_params["page"] == "2"

    await run()


@pytest.mark.asyncio
async def test_list_credits_api_error(mock_credit_error_response):
    """Test the list_credits command handling API errors."""

    @patch("aiohttp.ClientSession.get")
    async def run(mock_get):
        mock_get.return_value = mock_credit_error_response

        # Run the list_credits command and expect it to handle the error
        with pytest.raises(ClientResponseError):
            await list_credits(
                page_size=100,
                page=1,
                min_balance=None,
                json=False,
            )

    await run()
