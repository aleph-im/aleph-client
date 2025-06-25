from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import ClientResponseError
from aleph.sdk.types import PortFlags
from aleph_message.models import InstanceMessage, ItemHash
from aleph_message.status import MessageStatus

from aleph_client.commands.instance.port_forwarder import (
    create,
    delete,
    list_ports,
    refresh,
    update,
)

from .mocks import FAKE_CRN_BASIC_URL, FAKE_VM_HASH, create_mock_load_account


@pytest.fixture
def mock_auth_setup():
    """Create a common mock setup that can be used across all tests"""
    # Mock account
    mock_account = MagicMock()
    mock_account.get_address.return_value = "0x941B13FE26aF62C288108224FcD6fE03F71E189F"

    mock_load_account = create_mock_load_account()
    mock_load_account.return_value = mock_account

    # Mock port message
    mock_port_message = MagicMock(item_hash=FAKE_VM_HASH)

    # Create a proper mock for the crn service
    mock_crn_service = MagicMock()
    mock_crn_service.get_crns_list = AsyncMock(return_value={"crns": []})
    mock_crn_service.update_instance_config = AsyncMock(return_value="Port configurations updated successfully")

    # Mock port forwarder service
    mock_port_forwarder = MagicMock()
    mock_port_forwarder.create_port = AsyncMock(return_value=(mock_port_message, MessageStatus.PROCESSED))
    mock_port_forwarder.get_port = AsyncMock()
    mock_port_forwarder.get_ports = AsyncMock()
    mock_port_forwarder.update_port = AsyncMock(return_value=(mock_port_message, MessageStatus.PROCESSED))
    mock_port_forwarder.delete_ports = AsyncMock(return_value=(mock_port_message, MessageStatus.PROCESSED))

    # Mock instance service
    mock_instance_service = MagicMock()
    mock_instance_service.get_name_of_executable = AsyncMock(return_value="test-instance")

    # Mock utils service
    mock_utils_service = MagicMock()
    mock_utils_service.get_name_of_executable = AsyncMock(return_value="test-instance")
    mock_utils_service.get_instance_allocation_info = AsyncMock()

    # Create client
    mock_client = AsyncMock()
    mock_client.crn = mock_crn_service
    mock_client.port_forwarder = mock_port_forwarder
    mock_client.instance = mock_instance_service
    mock_client.instance = mock_utils_service
    mock_client.get_message = AsyncMock(return_value=MagicMock(spec=InstanceMessage))

    # Create client class
    mock_client_class = MagicMock()
    mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

    return {
        "mock_load_account": mock_load_account,
        "mock_account": mock_account,
        "mock_client": mock_client,
        "mock_client_class": mock_client_class,
        "mock_port_message": mock_port_message,
    }


@pytest.mark.asyncio
async def test_list_ports(mock_auth_setup):
    """Test the list_ports function"""
    # Get mocks from fixture
    mock_load_account = mock_auth_setup["mock_load_account"]
    mock_client = mock_auth_setup["mock_client"]
    mock_client_class = mock_auth_setup["mock_client_class"]

    # Mock port config response with sample data
    mock_port_config = MagicMock()
    mock_port_config.data = [
        MagicMock(
            root={
                FAKE_VM_HASH: MagicMock(ports={22: PortFlags(tcp=True, udp=False), 80: PortFlags(tcp=True, udp=True)})
            }
        )
    ]

    mock_client.port_forwarder.get_ports.return_value = mock_port_config
    mock_console = MagicMock()

    with (
        patch("aleph_client.commands.instance.port_forwarder._load_account", mock_load_account),
        patch("aleph_client.commands.instance.port_forwarder.AlephHttpClient", mock_client_class),
        patch("aleph_client.commands.instance.port_forwarder.Console", return_value=mock_console),
    ):
        # Test with default parameters
        await list_ports()

        # Check function calls
        mock_load_account.assert_called_once()
        mock_client.port_forwarder.get_ports.assert_called_once()
        mock_client.instance.get_name_of_executable.assert_called()
        mock_console.print.assert_called()

    # Test when no ports are found
    mock_client.port_forwarder.get_ports.reset_mock()
    mock_client.port_forwarder.get_ports.side_effect = ClientResponseError(
        request_info=MagicMock(), history=(), status=404
    )

    with (
        patch("aleph_client.commands.instance.port_forwarder._load_account", mock_load_account),
        patch("aleph_client.commands.instance.port_forwarder.AlephHttpClient", mock_client_class),
        patch("aleph_client.commands.instance.port_forwarder.typer.echo") as mock_echo,
        patch("aleph_client.commands.instance.port_forwarder.typer.Exit", side_effect=SystemExit),
    ):
        try:
            # Test with specific item_hash
            await list_ports(item_hash=FAKE_VM_HASH)
        except SystemExit:
            pass

        mock_client.port_forwarder.get_ports.assert_called_once()
        mock_echo.assert_any_call("No port forwards found for address: 0x941B13FE26aF62C288108224FcD6fE03F71E189F")


@pytest.mark.asyncio
async def test_create_port(mock_auth_setup):
    """Test the create function"""
    # Get mocks from fixture
    mock_load_account = mock_auth_setup["mock_load_account"]
    mock_client = mock_auth_setup["mock_client"]
    mock_client_class = mock_auth_setup["mock_client_class"]

    with (
        patch("aleph_client.commands.instance.port_forwarder._load_account", mock_load_account),
        patch("aleph_client.commands.instance.port_forwarder.AuthenticatedAlephHttpClient", mock_client_class),
        patch("aleph_client.commands.instance.port_forwarder.typer.echo") as mock_echo,
    ):
        # Test with TCP only
        await create(item_hash=FAKE_VM_HASH, port=22, tcp=True, udp=False)

        # Check function calls
        mock_load_account.assert_called_once()
        mock_client.port_forwarder.create_port.assert_called_once()

        # Verify correct arguments were passed
        call_args = mock_client.port_forwarder.create_port.call_args[1]
        assert call_args["item_hash"] == ItemHash(FAKE_VM_HASH)
        assert 22 in call_args["ports"].ports
        assert call_args["ports"].ports[22].tcp is True
        assert call_args["ports"].ports[22].udp is False

        # Check that success message was printed
        mock_echo.assert_any_call(f"Port forward created successfully for {FAKE_VM_HASH} on port 22")


@pytest.mark.asyncio
async def test_update_port(mock_auth_setup):
    """Test the update function"""
    mock_load_account = mock_auth_setup["mock_load_account"]
    mock_client = mock_auth_setup["mock_client"]
    mock_client_class = mock_auth_setup["mock_client_class"]

    mock_existing_ports = MagicMock()
    mock_existing_ports.ports = {22: PortFlags(tcp=True, udp=False), 80: PortFlags(tcp=True, udp=True)}

    mock_client.port_forwarder.get_port.return_value = mock_existing_ports

    with (
        patch("aleph_client.commands.instance.port_forwarder._load_account", mock_load_account),
        patch("aleph_client.commands.instance.port_forwarder.AlephHttpClient", mock_client_class),
        patch("aleph_client.commands.instance.port_forwarder.AuthenticatedAlephHttpClient", mock_client_class),
        patch("aleph_client.commands.instance.port_forwarder.typer.echo") as mock_echo,
    ):
        await update(item_hash=FAKE_VM_HASH, port=22, tcp=True, udp=True)

        mock_load_account.assert_called_once()
        mock_client.port_forwarder.get_port.assert_called_once()
        mock_client.port_forwarder.update_port.assert_called_once()

        call_args = mock_client.port_forwarder.update_port.call_args[1]
        assert call_args["item_hash"] == ItemHash(FAKE_VM_HASH)
        assert 22 in call_args["ports"].ports
        assert call_args["ports"].ports[22].tcp is True
        assert call_args["ports"].ports[22].udp is True
        assert 80 in call_args["ports"].ports

        mock_echo.assert_any_call(f"Port forward updated successfully for {FAKE_VM_HASH} on port 22")


@pytest.mark.asyncio
async def test_delete_port(mock_auth_setup):
    """Test the delete function"""
    mock_load_account = mock_auth_setup["mock_load_account"]
    mock_client = mock_auth_setup["mock_client"]
    mock_client_class = mock_auth_setup["mock_client_class"]

    mock_existing_ports = MagicMock()
    mock_existing_ports.ports = {22: PortFlags(tcp=True, udp=False), 80: PortFlags(tcp=True, udp=True)}

    mock_client.port_forwarder.get_port.return_value = mock_existing_ports

    with (
        patch("aleph_client.commands.instance.port_forwarder._load_account", mock_load_account),
        patch("aleph_client.commands.instance.port_forwarder.AlephHttpClient", mock_client_class),
        patch("aleph_client.commands.instance.port_forwarder.AuthenticatedAlephHttpClient", mock_client_class),
        patch("aleph_client.commands.instance.port_forwarder.typer.echo") as mock_echo,
    ):
        # Test deleting a specific port
        await delete(item_hash=FAKE_VM_HASH, port=22)

        mock_load_account.assert_called_once()
        mock_client.port_forwarder.get_port.assert_called_once()
        mock_client.port_forwarder.update_port.assert_called_once()

        call_args = mock_client.port_forwarder.update_port.call_args[1]
        assert call_args["item_hash"] == ItemHash(FAKE_VM_HASH)
        assert 22 not in call_args["ports"].ports
        assert 80 in call_args["ports"].ports

        mock_echo.assert_any_call(f"Port forward deleted successfully for {FAKE_VM_HASH} on port 22")

    mock_load_account.reset_mock()
    mock_client.port_forwarder.get_port.reset_mock()
    mock_client.port_forwarder.update_port.reset_mock()
    mock_client.port_forwarder.delete_ports.reset_mock()

    with (
        patch("aleph_client.commands.instance.port_forwarder._load_account", mock_load_account),
        patch("aleph_client.commands.instance.port_forwarder.AlephHttpClient", mock_client_class),
        patch("aleph_client.commands.instance.port_forwarder.AuthenticatedAlephHttpClient", mock_client_class),
        patch("aleph_client.commands.instance.port_forwarder.typer.echo") as mock_echo,
    ):
        await delete(item_hash=FAKE_VM_HASH, port=None)

        mock_load_account.assert_called_once()
        mock_client.port_forwarder.get_port.assert_called_once()
        mock_client.port_forwarder.delete_ports.assert_called_once()

        call_args = mock_client.port_forwarder.delete_ports.call_args[1]
        assert call_args["item_hash"] == ItemHash(FAKE_VM_HASH)

        mock_echo.assert_any_call(f"All port forwards deleted successfully for {FAKE_VM_HASH}")


@pytest.mark.asyncio
async def test_delete_port_last_port(mock_auth_setup):
    """Test deleting the last port which should trigger delete_ports instead of update_port"""
    mock_load_account = mock_auth_setup["mock_load_account"]
    mock_client = mock_auth_setup["mock_client"]
    mock_client_class = mock_auth_setup["mock_client_class"]

    mock_existing_ports = MagicMock()
    mock_existing_ports.ports = {22: PortFlags(tcp=True, udp=False)}

    mock_client.port_forwarder.get_port.return_value = mock_existing_ports

    mock_client.port_forwarder.update_port = None

    with (
        patch("aleph_client.commands.instance.port_forwarder._load_account", mock_load_account),
        patch("aleph_client.commands.instance.port_forwarder.AlephHttpClient", mock_client_class),
        patch("aleph_client.commands.instance.port_forwarder.AuthenticatedAlephHttpClient", mock_client_class),
        patch("aleph_client.commands.instance.port_forwarder.typer.echo") as mock_echo,
    ):
        await delete(item_hash=FAKE_VM_HASH, port=22)

        # Check function calls
        mock_load_account.assert_called_once()
        mock_client.port_forwarder.get_port.assert_called_once()

        # Verify delete_ports was called
        mock_client.port_forwarder.delete_ports.assert_called_once()

        # Verify correct arguments were passed to delete_ports
        call_args = mock_client.port_forwarder.delete_ports.call_args[1]
        assert call_args["item_hash"] == ItemHash(FAKE_VM_HASH)

        # Check that success message was printed
        mock_echo.assert_any_call(f"Port forward deleted successfully for {FAKE_VM_HASH} on port 22")


@pytest.mark.asyncio
async def test_refresh_port(mock_auth_setup):
    """Test the refresh function"""
    mock_load_account = mock_auth_setup["mock_load_account"]
    mock_client = mock_auth_setup["mock_client"]
    mock_client_class = mock_auth_setup["mock_client_class"]

    mock_allocation = MagicMock()
    mock_allocation.__class__.__name__ = "InstanceManual"
    mock_allocation.crn_url = FAKE_CRN_BASIC_URL

    mock_allocations = MagicMock()
    mock_allocations.node = MagicMock()
    mock_allocations.node.url = "node_url"

    mock_allocation.allocations = mock_allocations

    mock_client.instance.get_instance_allocation_info.return_value = (None, mock_allocation)

    with (
        patch("aleph_client.commands.instance.port_forwarder._load_account", mock_load_account),
        patch("aleph_client.commands.instance.port_forwarder.AuthenticatedAlephHttpClient", mock_client_class),
        patch("aleph_client.commands.instance.port_forwarder.typer.echo") as mock_echo,
    ):
        await refresh(item_hash=FAKE_VM_HASH)

        # Check function calls
        mock_load_account.assert_called_once()
        mock_client.get_message.assert_called_once_with(item_hash=FAKE_VM_HASH, message_type=InstanceMessage)
        mock_client.crn.get_crns_list.assert_called_once()
        mock_client.instance.get_instance_allocation_info.assert_called_once()

        args, kwargs = mock_client.crn.update_instance_config.call_args
        assert "item_hash" in kwargs and kwargs["item_hash"] == FAKE_VM_HASH
        assert "crn_address" in kwargs

        # Check that success message was printed
        mock_echo.assert_called_with("Port configurations updated successfully")


@pytest.mark.asyncio
async def test_refresh_port_no_allocation(mock_auth_setup):
    """Test the refresh function when no allocation is found"""
    mock_load_account = mock_auth_setup["mock_load_account"]
    mock_client = mock_auth_setup["mock_client"]
    mock_client_class = mock_auth_setup["mock_client_class"]

    mock_client.instance.get_instance_allocation_info.return_value = (None, None)

    with (
        patch("aleph_client.commands.instance.port_forwarder._load_account", mock_load_account),
        patch("aleph_client.commands.instance.port_forwarder.AuthenticatedAlephHttpClient", mock_client_class),
        patch("aleph_client.commands.instance.port_forwarder.typer.echo") as mock_echo,
        patch("aleph_client.commands.instance.port_forwarder.typer.Exit", side_effect=SystemExit),
    ):
        with pytest.raises(SystemExit):
            await refresh(item_hash=FAKE_VM_HASH)

        mock_load_account.assert_called_once()
        mock_client.get_message.assert_called_once_with(item_hash=FAKE_VM_HASH, message_type=InstanceMessage)
        mock_client.crn.get_crns_list.assert_called_once()
        mock_client.instance.get_instance_allocation_info.assert_called_once()

        mock_echo.assert_called_with("No allocation Found")

        assert not mock_client.crn.update_instance_config.called


@pytest.mark.asyncio
async def test_refresh_port_scheduler_allocation(mock_auth_setup):
    """Test the refresh function with InstanceScheduler allocation type"""
    mock_load_account = mock_auth_setup["mock_load_account"]
    mock_client = mock_auth_setup["mock_client"]
    mock_client_class = mock_auth_setup["mock_client_class"]

    mock_allocation = MagicMock()
    mock_allocation.__class__.__name__ = "InstanceScheduler"

    mock_allocations = MagicMock()
    mock_allocations.node = MagicMock()
    mock_allocations.node.url = "scheduler_node_url"
    mock_allocation.allocations = mock_allocations

    mock_client.instance.get_instance_allocation_info.return_value = (None, mock_allocation)

    with (
        patch("aleph_client.commands.instance.port_forwarder._load_account", mock_load_account),
        patch("aleph_client.commands.instance.port_forwarder.AuthenticatedAlephHttpClient", mock_client_class),
        patch("aleph_client.commands.instance.port_forwarder.typer.echo") as mock_echo,
    ):
        await refresh(item_hash=FAKE_VM_HASH)

        mock_load_account.assert_called_once()
        mock_client.get_message.assert_called_once_with(item_hash=FAKE_VM_HASH, message_type=InstanceMessage)
        mock_client.crn.get_crns_list.assert_called_once()
        mock_client.instance.get_instance_allocation_info.assert_called_once()

        args, kwargs = mock_client.crn.update_instance_config.call_args
        assert "crn_address" in kwargs and kwargs["crn_address"] == "scheduler_node_url"
        assert "item_hash" in kwargs and kwargs["item_hash"] == FAKE_VM_HASH

        mock_echo.assert_called_with("Port configurations updated successfully")


@pytest.mark.asyncio
async def test_non_processed_message_statuses():
    """Test handling of non-PROCESSED message statuses in update and delete functions"""
    mock_load_account = create_mock_load_account()
    # Mock the clients
    mock_auth_client = AsyncMock()
    mock_auth_client_class = MagicMock()
    mock_auth_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_auth_client)
    mock_auth_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

    mock_http_client = AsyncMock()
    mock_http_client_class = MagicMock()
    mock_http_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_http_client)
    mock_http_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

    mock_existing_ports = MagicMock()
    mock_existing_ports.ports = {22: PortFlags(tcp=True, udp=False)}
    mock_http_client.port_forwarder = MagicMock()
    mock_http_client.port_forwarder.get_port = AsyncMock(return_value=mock_existing_ports)

    with (
        patch("aleph_client.commands.instance.port_forwarder._load_account", mock_load_account),
        patch("aleph_client.commands.instance.port_forwarder.AlephHttpClient", mock_http_client_class),
        patch("aleph_client.commands.instance.port_forwarder.AuthenticatedAlephHttpClient", mock_auth_client_class),
        patch("aleph_client.commands.instance.port_forwarder.typer.echo") as mock_echo,
    ):
        port_forwarder_mock = MagicMock()
        port_forwarder_mock.update_port = AsyncMock(return_value=("mock_message", MessageStatus.PENDING))
        mock_auth_client.port_forwarder = port_forwarder_mock

        await update(item_hash=FAKE_VM_HASH, port=22, tcp=True, udp=True)

        mock_echo.assert_any_call(
            f"Port forward update request was accepted but not yet processed. Status: {MessageStatus.PENDING}"
        )
        mock_echo.reset_mock()

    with (
        patch("aleph_client.commands.instance.port_forwarder._load_account", mock_load_account),
        patch("aleph_client.commands.instance.port_forwarder.AlephHttpClient", mock_http_client_class),
        patch("aleph_client.commands.instance.port_forwarder.AuthenticatedAlephHttpClient", mock_auth_client_class),
        patch("aleph_client.commands.instance.port_forwarder.typer.echo") as mock_echo,
    ):
        port_forwarder_mock = MagicMock()
        port_forwarder_mock.update_port = AsyncMock(return_value=("mock_message", MessageStatus.PENDING))
        port_forwarder_mock.delete_ports = AsyncMock(return_value=("mock_message", MessageStatus.PENDING))
        mock_auth_client.port_forwarder = port_forwarder_mock

        await delete(item_hash=FAKE_VM_HASH, port=22)

        mock_echo.assert_any_call(
            f"Port forward delete request was accepted but not yet processed. Status: {MessageStatus.PENDING}"
        )
        mock_echo.reset_mock()

    with (
        patch("aleph_client.commands.instance.port_forwarder._load_account", mock_load_account),
        patch("aleph_client.commands.instance.port_forwarder.AlephHttpClient", mock_http_client_class),
        patch("aleph_client.commands.instance.port_forwarder.AuthenticatedAlephHttpClient", mock_auth_client_class),
        patch("aleph_client.commands.instance.port_forwarder.typer.echo") as mock_echo,
    ):
        port_forwarder_mock = MagicMock()
        port_forwarder_mock.update_port = AsyncMock(return_value=("mock_message", MessageStatus.PENDING))
        port_forwarder_mock.delete_ports = AsyncMock(return_value=("mock_message", MessageStatus.PENDING))
        mock_auth_client.port_forwarder = port_forwarder_mock

        await delete(item_hash=FAKE_VM_HASH, port=None)

        mock_echo.assert_any_call(
            f"Port forwards delete request was accepted but not yet processed. Status: {MessageStatus.PENDING}"
        )
        mock_echo.reset_mock()
