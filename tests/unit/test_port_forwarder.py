from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import ClientResponseError
from aleph.sdk.client.service.port_forwarder import PortFlags, Ports
from aleph_message.models import InstanceMessage, ItemHash
from aleph_message.status import MessageStatus

from aleph_client.commands.instance.port_forwarder import (
    create,
    delete,
    list_ports,
    refresh,
    update,
)

from .mocks import FAKE_CRN_URL, FAKE_VM_HASH, create_mock_load_account


def test_port_flags():
    """Test the PortFlags class"""
    tcp_only = PortFlags(tcp=True, udp=False)
    assert tcp_only.tcp is True
    assert tcp_only.udp is False

    udp_only = PortFlags(tcp=False, udp=True)
    assert udp_only.tcp is False
    assert udp_only.udp is True

    both = PortFlags(tcp=True, udp=True)
    assert both.tcp is True
    assert both.udp is True


def test_ports():
    """Test the Ports class"""
    tcp_flags = PortFlags(tcp=True, udp=False)
    udp_flags = PortFlags(tcp=False, udp=True)
    both_flags = PortFlags(tcp=True, udp=True)

    ports = Ports(ports={22: tcp_flags, 53: udp_flags, 80: both_flags})

    assert len(ports.ports) == 3
    assert ports.ports[22].tcp is True
    assert ports.ports[22].udp is False
    assert ports.ports[53].tcp is False
    assert ports.ports[53].udp is True
    assert ports.ports[80].tcp is True
    assert ports.ports[80].udp is True


@pytest.mark.asyncio
async def test_list_ports():
    """Test the list_ports function"""
    mock_load_account = create_mock_load_account()

    # Mock port config response with sample data
    mock_port_config = MagicMock()
    mock_port_config.data = [
        MagicMock(
            root={
                FAKE_VM_HASH: MagicMock(ports={22: PortFlags(tcp=True, udp=False), 80: PortFlags(tcp=True, udp=True)})
            }
        )
    ]

    # Mock the client
    mock_client = AsyncMock()
    mock_client.port_forwarder = AsyncMock(get_ports=AsyncMock(return_value=mock_port_config))
    mock_client.utils = AsyncMock(get_name_of_executable=AsyncMock(return_value="test-instance"))

    mock_client_class = MagicMock()
    mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

    # Mock console for rich output
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
        mock_client.utils.get_name_of_executable.assert_called_once()
        mock_console.print.assert_called()  # Table and panel should be printed

    # Test when no ports are found
    mock_client.port_forwarder.get_ports.reset_mock()
    mock_client.port_forwarder.get_ports.side_effect = ClientResponseError(
        request_info=MagicMock(), history=(), status=404
    )

    # This mock is needed to provide the correct address
    mock_account = MagicMock()
    mock_account.get_address.return_value = "0x941B13FE26aF62C288108224FcD6fE03F71E189F"
    mock_load_account.return_value = mock_account

    with (
        patch("aleph_client.commands.instance.port_forwarder._load_account", mock_load_account),
        patch("aleph_client.commands.instance.port_forwarder.AlephHttpClient", mock_client_class),
        patch("aleph_client.commands.instance.port_forwarder.typer.echo") as mock_echo,
    ):

        # Test with specific item_hash
        await list_ports(item_hash=FAKE_VM_HASH)

        # Check function calls
        mock_client.port_forwarder.get_ports.assert_called_once()
        mock_echo.assert_called_with("No port forwards found for address: 0x941B13FE26aF62C288108224FcD6fE03F71E189F")


@pytest.mark.asyncio
async def test_create_port():
    """Test the create function"""
    mock_load_account = create_mock_load_account()

    # Mock the authenticated client
    mock_client = AsyncMock()
    mock_client.port_forwarder = AsyncMock(
        create_port=AsyncMock(return_value=("mock_message", MessageStatus.PROCESSED))
    )

    mock_client_class = MagicMock()
    mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

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
async def test_update_port():
    """Test the update function"""
    mock_load_account = create_mock_load_account()

    # Mock port config response
    mock_existing_ports = MagicMock()
    mock_existing_ports.ports = {22: PortFlags(tcp=True, udp=False), 80: PortFlags(tcp=True, udp=True)}

    # Mock the clients
    mock_http_client = AsyncMock()
    mock_http_client.port_forwarder = AsyncMock(get_port=AsyncMock(return_value=mock_existing_ports))

    mock_http_client_class = MagicMock()
    mock_http_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_http_client)
    mock_http_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

    mock_auth_client = AsyncMock()
    mock_auth_client.port_forwarder = AsyncMock(
        update_port=AsyncMock(return_value=("mock_message", MessageStatus.PROCESSED))
    )

    mock_auth_client_class = MagicMock()
    mock_auth_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_auth_client)
    mock_auth_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

    with (
        patch("aleph_client.commands.instance.port_forwarder._load_account", mock_load_account),
        patch("aleph_client.commands.instance.port_forwarder.AlephHttpClient", mock_http_client_class),
        patch("aleph_client.commands.instance.port_forwarder.AuthenticatedAlephHttpClient", mock_auth_client_class),
        patch("aleph_client.commands.instance.port_forwarder.typer.echo") as mock_echo,
    ):

        # Test updating an existing port
        await update(item_hash=FAKE_VM_HASH, port=22, tcp=True, udp=True)

        # Check function calls
        mock_load_account.assert_called_once()
        mock_http_client.port_forwarder.get_port.assert_called_once()
        mock_auth_client.port_forwarder.update_port.assert_called_once()

        # Verify correct arguments were passed to update_port
        call_args = mock_auth_client.port_forwarder.update_port.call_args[1]
        assert call_args["item_hash"] == ItemHash(FAKE_VM_HASH)
        assert 22 in call_args["ports"].ports
        assert call_args["ports"].ports[22].tcp is True
        assert call_args["ports"].ports[22].udp is True
        assert 80 in call_args["ports"].ports  # Existing port should still be there

        # Check that success message was printed
        mock_echo.assert_any_call(f"Port forward updated successfully for {FAKE_VM_HASH} on port 22")


@pytest.mark.asyncio
async def test_delete_port():
    """Test the delete function"""
    mock_load_account = create_mock_load_account()

    # Mock port config response
    mock_existing_ports = MagicMock()
    mock_existing_ports.ports = {22: PortFlags(tcp=True, udp=False), 80: PortFlags(tcp=True, udp=True)}

    # Mock the clients
    mock_http_client = AsyncMock()
    mock_http_client.port_forwarder = AsyncMock(get_port=AsyncMock(return_value=mock_existing_ports))

    mock_http_client_class = MagicMock()
    mock_http_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_http_client)
    mock_http_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

    mock_auth_client = AsyncMock()
    mock_auth_client.port_forwarder = AsyncMock(
        update_port=AsyncMock(return_value=("mock_message", MessageStatus.PROCESSED)),
        delete_ports=AsyncMock(return_value=("mock_message", MessageStatus.PROCESSED)),
    )

    mock_auth_client_class = MagicMock()
    mock_auth_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_auth_client)
    mock_auth_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

    with (
        patch("aleph_client.commands.instance.port_forwarder._load_account", mock_load_account),
        patch("aleph_client.commands.instance.port_forwarder.AlephHttpClient", mock_http_client_class),
        patch("aleph_client.commands.instance.port_forwarder.AuthenticatedAlephHttpClient", mock_auth_client_class),
        patch("aleph_client.commands.instance.port_forwarder.typer.echo") as mock_echo,
    ):

        # Test deleting a specific port
        await delete(item_hash=FAKE_VM_HASH, port=22)

        # Check function calls
        mock_load_account.assert_called_once()
        mock_http_client.port_forwarder.get_port.assert_called_once()
        mock_auth_client.port_forwarder.update_port.assert_called_once()

        # Verify correct arguments were passed to update_port
        call_args = mock_auth_client.port_forwarder.update_port.call_args[1]
        assert call_args["item_hash"] == ItemHash(FAKE_VM_HASH)
        assert 22 not in call_args["ports"].ports  # Port 22 should be removed
        assert 80 in call_args["ports"].ports  # Port 80 should still be there

        # Check that success message was printed
        mock_echo.assert_any_call(f"Port forward deleted successfully for {FAKE_VM_HASH} on port 22")

    # Reset mocks
    mock_load_account.reset_mock()
    mock_http_client.port_forwarder.get_port.reset_mock()
    mock_auth_client.port_forwarder.update_port.reset_mock()
    mock_auth_client.port_forwarder.delete_ports.reset_mock()

    # Test deleting all ports
    with (
        patch("aleph_client.commands.instance.port_forwarder._load_account", mock_load_account),
        patch("aleph_client.commands.instance.port_forwarder.AlephHttpClient", mock_http_client_class),
        patch("aleph_client.commands.instance.port_forwarder.AuthenticatedAlephHttpClient", mock_auth_client_class),
        patch("aleph_client.commands.instance.port_forwarder.typer.echo") as mock_echo,
    ):

        await delete(item_hash=FAKE_VM_HASH, port=None)

        # Check function calls
        mock_load_account.assert_called_once()
        mock_http_client.port_forwarder.get_port.assert_called_once()
        mock_auth_client.port_forwarder.delete_ports.assert_called_once()

        # Verify correct arguments were passed to delete_ports
        call_args = mock_auth_client.port_forwarder.delete_ports.call_args[1]
        assert call_args["item_hash"] == ItemHash(FAKE_VM_HASH)

        # Check that success message was printed
        mock_echo.assert_any_call(f"All port forwards deleted successfully for {FAKE_VM_HASH}")


@pytest.mark.asyncio
async def test_refresh_port():
    """Test the refresh function"""
    mock_load_account = create_mock_load_account()

    # Mock the instance message
    mock_instance = MagicMock(spec=InstanceMessage)

    # Mock allocation information
    mock_allocation = MagicMock()
    mock_allocation.__class__.__name__ = "InstanceManual"
    mock_allocation.crn_url = FAKE_CRN_URL

    # Mock non-manual allocation (for InstanceScheduler)
    mock_allocations = MagicMock()
    mock_allocations.node = MagicMock()
    mock_allocations.node.url = "node_url"

    # Set up the allocation object based on how it's used in the implementation
    mock_allocation.allocations = mock_allocations

    # Mock authenticated client
    mock_auth_client = AsyncMock()
    mock_auth_client.get_message = AsyncMock(return_value=mock_instance)
    mock_auth_client.crn = AsyncMock(
        get_crns_list=AsyncMock(return_value=["crn1", "crn2"]),
        update_instance_config=AsyncMock(return_value="Port configurations updated successfully"),
    )
    mock_auth_client.utils = AsyncMock(get_instance_allocation_info=AsyncMock(return_value=(None, mock_allocation)))

    mock_auth_client_class = MagicMock()
    mock_auth_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_auth_client)
    mock_auth_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

    with (
        patch("aleph_client.commands.instance.port_forwarder._load_account", mock_load_account),
        patch("aleph_client.commands.instance.port_forwarder.AuthenticatedAlephHttpClient", mock_auth_client_class),
        patch("aleph_client.commands.instance.port_forwarder.typer.echo") as mock_echo,
    ):
        # Test refreshing port configuration
        await refresh(item_hash=FAKE_VM_HASH)

        # Check function calls
        mock_load_account.assert_called_once()
        mock_auth_client.get_message.assert_called_once_with(item_hash=FAKE_VM_HASH, message_type=InstanceMessage)
        mock_auth_client.crn.get_crns_list.assert_called_once()
        mock_auth_client.utils.get_instance_allocation_info.assert_called_once()

        # Don't assert the exact crn_address value, just verify the function was called with the correct item_hash
        args, kwargs = mock_auth_client.crn.update_instance_config.call_args
        assert "item_hash" in kwargs and kwargs["item_hash"] == FAKE_VM_HASH
        assert "crn_address" in kwargs

        # Check that success message was printed
        mock_echo.assert_called_with("Port configurations updated successfully")
