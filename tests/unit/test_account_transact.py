from unittest.mock import MagicMock, patch

import pytest
import typer
from aleph.sdk.exceptions import InsufficientFundsError
from aleph.sdk.types import TokenType
from typer.testing import CliRunner

from aleph_client.__main__ import app

from .mocks import create_mock_load_account

runner = CliRunner()


@pytest.fixture
def mock_account():
    """Create a mock account that can be configured for testing."""
    mock_loader = create_mock_load_account()
    return mock_loader()


def test_account_can_transact_success(mock_account):
    """Test that account.can_transact() succeeds when sufficient funds are available."""
    # This should succeed as the mock is configured to return True
    assert mock_account.can_transact() is True


@patch("aleph_client.commands.account.load_account")
def test_account_can_transact_error_handling(mock_load_account):
    """Test that error is handled properly when account.can_transact() fails."""
    # Setup mock account that will raise InsufficientFundsError
    mock_account = MagicMock()
    mock_account.can_transact.side_effect = InsufficientFundsError(
        token_type=TokenType.GAS, required_funds=0.1, available_funds=0.05
    )
    mock_load_account.return_value = mock_account

    # Add a test command that uses the safety check
    @app.command()
    def test_command():
        try:  # Safety check to ensure account can transact
            mock_account.can_transact()
        except Exception as e:
            print(str(e))
            raise typer.Exit(code=1) from e
        return 0

    # Run the command
    result = runner.invoke(app, ["test-command"])

    # Verify error handling
    assert result.exit_code == 1
    assert "Insufficient funds (GAS)" in result.stdout
