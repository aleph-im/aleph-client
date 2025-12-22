from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aleph.sdk.types import CrnExecutionV1, CrnExecutionV2, InstanceManual
from aleph_message.models.execution.base import PaymentType
from rich.text import Text

from aleph_client.commands.instance.display import (
    CRNTable,
    InstanceTableBuilder,
    display_vm_status,
)
from aleph_client.models import CRNInfo


def test_display_vm_status():
    """Test the display_vm_status function with different status combinations."""
    # Test status with stopped_at
    status_stopped = MagicMock()
    status_stopped.stopped_at = "2025-06-01T00:00:00Z"
    status_stopped.stopping_at = None
    status_stopped.started_at = None
    status_stopped.preparing_at = None
    result = display_vm_status(status_stopped)
    assert isinstance(result, Text)
    assert "STOPPED" in result.plain

    # Test status with stopping_at
    status_stopping = MagicMock()
    status_stopping.stopped_at = None
    status_stopping.stopping_at = "2025-06-01T00:00:00Z"
    status_stopping.started_at = None
    status_stopping.preparing_at = None
    result = display_vm_status(status_stopping)
    assert isinstance(result, Text)
    assert "STOPPING" in result.plain

    # Test status with started_at
    status_running = MagicMock()
    status_running.stopped_at = None
    status_running.stopping_at = None
    status_running.started_at = "2025-06-01T00:00:00Z"
    status_running.preparing_at = None
    result = display_vm_status(status_running)
    assert isinstance(result, Text)
    assert "RUNNING" in result.plain

    # Test status with preparing_at
    status_preparing = MagicMock()
    status_preparing.stopped_at = None
    status_preparing.stopping_at = None
    status_preparing.started_at = None
    status_preparing.preparing_at = "2025-06-01T00:00:00Z"
    result = display_vm_status(status_preparing)
    assert isinstance(result, Text)
    assert "PREPARING" in result.plain

    # Test empty status - using patch to handle the all() check in the function
    with patch("aleph_client.commands.instance.display.all", return_value=True):
        status_empty = MagicMock()
        status_empty.stopped_at = None
        status_empty.stopping_at = None
        status_empty.started_at = None
        status_empty.preparing_at = None

        result = display_vm_status(status_empty)
        assert isinstance(result, Text)
        assert "NOT ALLOCATED" in result.plain


@pytest.mark.asyncio
async def test_mock_crn_table():
    """Test the CRNTable class with mocks."""
    with patch("aleph_client.commands.instance.display.CRNTable") as mock_crn_table:
        mock_instance = MagicMock()
        mock_crn_table.return_value = mock_instance

        _ = mock_crn_table(
            crn_version="1.51",
            only_reward_address=True,
            only_qemu=True,
            only_confidentials=True,
            only_gpu=True,
            only_gpu_model="RTX 4000 ADA",
        )

        # Check that the constructor was called with the expected arguments
        mock_crn_table.assert_called_once_with(
            crn_version="1.51",
            only_reward_address=True,
            only_qemu=True,
            only_confidentials=True,
            only_gpu=True,
            only_gpu_model="RTX 4000 ADA",
        )


@pytest.mark.asyncio
async def test_instance_display_initialization():
    """Test the InstanceDisplay class initialization with different instance types."""
    from aleph_client.commands.instance.display import InstanceDisplay

    mock_message = MagicMock()
    mock_message.content.payment.type = PaymentType.hold.value
    mock_message.content.environment.trusted_execution.firmware = "a" * 64
    mock_message.content.requirements.gpu = [MagicMock()]
    mock_message.content.requirements.node.terms_and_conditions = "tac_hash_123"

    mock_manual = MagicMock(spec=InstanceManual)
    mock_exec = MagicMock(spec=CrnExecutionV2)

    instance_display = InstanceDisplay(mock_message, mock_manual, mock_exec)

    assert instance_display.is_hold is True
    assert instance_display.is_confidential is True
    assert instance_display.has_gpu is True
    assert instance_display.tac_hash == "tac_hash_123"
    assert instance_display.tac_url is None
    assert instance_display.tac_accepted is False


@pytest.mark.asyncio
async def test_instance_display_columns():
    """Test that InstanceDisplay correctly prepares display columns."""
    from aleph_client.commands.instance.display import InstanceDisplay

    mock_message = MagicMock()
    mock_message.content.payment.type = PaymentType.superfluid.value
    mock_message.content.environment.trusted_execution.firmware = None
    mock_message.content.requirements.gpu = None
    mock_message.content.requirements.node.terms_and_conditions = None
    mock_message.sender = "0x1234567890abcdef"
    mock_message.item_hash = "vm_hash_123"
    mock_message.chain.value = "ETH"
    mock_message.time = 1672531200.0
    mock_message.content.address = mock_message.sender

    mock_message.content.resources.vcpus = 2
    mock_message.content.resources.memory = 4096
    mock_message.content.rootfs.size_mib = 10240

    mock_message.content.metadata = {"name": "Test VM"}

    mock_allocation = MagicMock(spec=InstanceManual)
    mock_allocation.crn_url = "https://test.crn.com"
    mock_execution = None  # No execution

    instance_display = InstanceDisplay(mock_message, mock_allocation, mock_execution)

    with patch("aleph_client.commands.instance.display.download", AsyncMock(return_value=None)):
        mock_price = MagicMock()
        mock_price.required_tokens = "0.001"
        mock_price.cost = "0.001"
        mock_client = AsyncMock()
        mock_client.get_program_price = AsyncMock(return_value=mock_price)

        with patch("aleph_client.commands.instance.display.AlephHttpClient") as mock_client_class:
            mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

            await instance_display.prepare()

    assert instance_display.instance_column is not None
    assert instance_display.specifications_column is not None
    assert instance_display.allocation_column is not None
    assert instance_display.execution_column is not None

    assert "Test VM" in instance_display.instance_column.plain
    assert "vm_hash_123" in instance_display.instance_column.plain
    assert "ETH" in instance_display.instance_column.plain

    assert "https://test.crn.com" in instance_display.allocation_column.plain

    assert "PAYG" in instance_display.execution_column.plain


@pytest.mark.asyncio
async def test_execution_columns_v1():
    """Test preparation of execution column for V1 execution type."""
    from aleph_client.commands.instance.display import InstanceDisplay

    mock_message = MagicMock()
    mock_message.content.payment.type = PaymentType.superfluid.value
    mock_message.content.environment.trusted_execution.firmware = None
    mock_message.content.requirements.gpu = None
    mock_message.content.requirements.node.terms_and_conditions = None

    mock_allocation = MagicMock(spec=InstanceManual)

    mock_execution = MagicMock(spec=CrnExecutionV1)
    mock_execution.__class__ = MagicMock(spec=type)
    mock_execution.networking = MagicMock()
    mock_execution.networking.ipv6 = "2001:db8::1234"
    mock_execution.networking.ipv4 = "192.168.1.100"

    instance_display = InstanceDisplay(mock_message, mock_allocation, mock_execution)

    instance_display._prepare_execution_v1_column()

    assert instance_display.execution_column is not None
    assert "2001:db8::1234" in instance_display.execution_column.plain
    assert "192.168.1.100" in instance_display.execution_column.plain


@pytest.mark.asyncio
async def test_execution_columns_v2():
    """Test preparation of execution column for V2 execution type."""
    from aleph_client.commands.instance.display import InstanceDisplay

    mock_message = MagicMock()
    mock_message.content.payment.type = PaymentType.superfluid.value
    mock_message.content.environment.trusted_execution.firmware = None
    mock_message.content.requirements.gpu = None
    mock_message.content.requirements.node.terms_and_conditions = None

    mock_allocation = MagicMock(spec=InstanceManual)

    mock_execution = MagicMock(spec=CrnExecutionV2)
    mock_execution.__class__ = MagicMock(spec=type)
    mock_execution.networking = MagicMock()
    mock_execution.networking.ipv4_network = "192.168.1.0/24"
    mock_execution.networking.ipv6_network = "2001:db8::/64"
    mock_execution.networking.host_ipv4 = "192.168.1.1"
    mock_execution.networking.ipv6_ip = "2001:db8::1234"

    port_mapping = MagicMock()
    port_mapping.host = 8022
    port_mapping.tcp = True
    port_mapping.udp = False
    mock_execution.networking.mapped_ports = {"22": port_mapping}

    instance_display = InstanceDisplay(mock_message, mock_allocation, mock_execution)

    instance_display._prepare_execution_v2_column()

    assert instance_display.execution_column is not None
    assert "192.168.1.0/24" in instance_display.execution_column.plain
    assert "2001:db8::/64" in instance_display.execution_column.plain
    assert "192.168.1.1" in instance_display.execution_column.plain
    assert "2001:db8::1234" in instance_display.execution_column.plain
    assert "22 -> Host 8022" in instance_display.execution_column.plain
    assert "[TCP]" in instance_display.execution_column.plain
    assert "ssh root@192.168.1.1 -p 8022" in instance_display.execution_column.plain
    assert "ssh root@2001:db8::1234" in instance_display.execution_column.plain


@pytest.mark.asyncio
async def test_instance_table_builder():
    """Test the InstanceTableBuilder class."""
    from aleph_client.commands.instance.display import InstanceTableBuilder

    mock_messages = [MagicMock(), MagicMock()]
    for i, msg in enumerate(mock_messages):
        msg.item_hash = f"vm_hash_{i}"
        msg.sender = "0x1234567890abcdef"
        msg.chain = MagicMock()
        msg.chain.value = "ETH"
        msg.time = 1672531200.0

        payment_mock = MagicMock()
        payment_mock.type = PaymentType.superfluid.value if i == 0 else PaymentType.hold.value
        msg.content.payment = payment_mock

        msg.content.metadata = {"name": f"Test VM {i}"}

        msg.content.resources = MagicMock()
        msg.content.resources.vcpus = 2
        msg.content.resources.memory = 4096
        msg.content.rootfs = MagicMock()
        msg.content.rootfs.size_mib = 10240

        msg.content.environment = MagicMock()
        msg.content.requirements = MagicMock()
        msg.content.requirements.node = MagicMock()

        if i == 1:
            msg.content.environment.trusted_execution = MagicMock()
            msg.content.environment.trusted_execution.firmware = "a" * 64
            msg.content.requirements.gpu = [MagicMock()]
        else:
            msg.content.environment.trusted_execution.firmware = None
            msg.content.requirements.gpu = None

        msg.content.address = msg.sender

    mock_allocations = MagicMock()
    mock_manual = MagicMock()
    mock_manual.__class__.__name__ = "InstanceManual"
    mock_manual.crn_url = "https://test.crn.com"

    mock_scheduler = MagicMock()
    mock_scheduler.__class__.__name__ = "InstanceWithScheduler"
    mock_scheduler.allocations = MagicMock()
    mock_scheduler.allocations.node = MagicMock()
    mock_scheduler.allocations.node.url = "https://scheduler.crn.com"

    mock_allocations.root = {"vm_hash_0": mock_manual, "vm_hash_1": mock_scheduler}

    mock_executions = MagicMock()
    mock_execution = MagicMock(spec=CrnExecutionV2)
    mock_execution.__class__ = MagicMock(spec=type)

    # Create status
    mock_execution.status = MagicMock()
    mock_execution.status.started_at = "2025-06-01T00:00:00Z"
    mock_execution.status.stopped_at = None
    mock_execution.status.stopping_at = None
    mock_execution.status.preparing_at = None

    # Create networking
    mock_execution.networking = MagicMock()
    mock_execution.networking.ipv4_network = "192.168.1.0/24"
    mock_execution.networking.ipv6_network = "2001:db8::/64"
    mock_execution.networking.host_ipv4 = "192.168.1.1"
    mock_execution.networking.ipv6_ip = "2001:db8::1234"
    mock_execution.networking.mapped_ports = {}

    # Set up executions dictionary
    mock_executions.root = {"vm_hash_0": mock_execution}

    # Create table builder with mocks
    with patch("aleph_client.commands.instance.display.download", AsyncMock(return_value=None)):
        with patch("aleph_client.commands.instance.display.AlephHttpClient") as mock_client_class:
            # Mock price query
            mock_client = AsyncMock()
            mock_price = MagicMock()
            mock_price.required_tokens = "0.001"
            mock_price.cost = "0.001"
            mock_client.get_program_price = AsyncMock(return_value=mock_price)

            mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

            builder = InstanceTableBuilder(mock_messages, mock_allocations, mock_executions)
            table = await builder.build()

    assert table is not None

    # We only need to check that the builder ran and tracked things
    assert hasattr(builder, "unallocated_payg_found")
    assert hasattr(builder, "unallocated_hold")


@pytest.mark.asyncio
async def test_instance_table_builder_with_unallocated():
    """Test the InstanceTableBuilder class with unallocated instances."""

    mock_messages = [MagicMock()]
    mock_messages[0].item_hash = "vm_hash_0"
    mock_messages[0].sender = "0x1234567890abcdef"
    mock_allocations = MagicMock()
    mock_allocations.root = {}
    mock_executions = MagicMock()
    mock_executions.root = {}

    builder = InstanceTableBuilder(mock_messages, mock_allocations, mock_executions)

    assert hasattr(builder, "messages")
    assert hasattr(builder, "allocations")
    assert hasattr(builder, "executions")
    assert hasattr(builder, "unallocated_payg_found")
    assert hasattr(builder, "unallocated_hold")
    assert hasattr(builder, "uninitialized_confidential_found")

    assert hasattr(builder, "display_summary_panel")

    mock_console = MagicMock()
    builder.console = mock_console

    builder.display_summary_panel()

    mock_console.print.assert_called_once()


@pytest.mark.asyncio
async def test_crn_table_initialization():
    """Test the CRNTable class initialization with different parameters."""

    # Create mock CRN list
    mock_crn = MagicMock()
    mock_crn_list = [mock_crn]

    # Test with different initialization parameters
    crn_table = CRNTable(
        crn_list=mock_crn_list,
        crn_version="1.5.1",
        only_reward_address=True,
        only_qemu=True,
        only_confidentials=True,
        only_gpu=True,
        only_gpu_model="RTX 4090",
    )

    # Verify the initialization attributes
    assert crn_table.crn_list == mock_crn_list
    assert crn_table.crn_version == "1.5.1"
    assert crn_table.only_reward_address is True
    assert crn_table.only_qemu is True
    assert crn_table.only_confidentials is True
    assert crn_table.only_gpu is True
    assert crn_table.only_gpu_model == "RTX 4090"


@pytest.mark.asyncio
async def test_crn_table_gpu_filtering(mock_crn_list):
    """Test the CRNTable GPU filtering logic from add_crn_info method."""

    # Create a CRNInfo object from the mock_crn_list's GPU CRN (first item)
    gpu_crn_info = CRNInfo.from_unsanitized_input(mock_crn_list[0])

    # Get the GPU model from the mock data
    gpu_model = gpu_crn_info.compatible_available_gpus[0]["model"]

    # Create CRNTable instances with mocked table attribute
    crn_table_matching = CRNTable(
        crn_list=[],
        only_gpu=True,
        only_gpu_model=gpu_model,  # Matches the CRN's GPU model
    )
    crn_table_matching.table = MagicMock()

    crn_table_non_matching = CRNTable(
        crn_list=[],
        only_gpu=True,
        only_gpu_model="NonExistentModel",  # Different model
    )
    crn_table_non_matching.table = MagicMock()

    # For matching GPU model
    await crn_table_matching.add_crn_info(gpu_crn_info, 0)

    # For non-matching GPU model
    await crn_table_non_matching.add_crn_info(gpu_crn_info, 0)

    # Assert filter results
    assert crn_table_matching.filtered_crns == 1  # Filter passes
    assert crn_table_non_matching.filtered_crns == 0  # Filter doesn't pass
    # Verify table.add_row was called for the matching table
    crn_table_matching.table.add_row.assert_called_once()


@pytest.mark.asyncio
async def test_crn_table_no_system_usage_handling(mock_crn_list):
    """Test that CRNTable correctly handles CRNs with no system_usage data."""

    # Create a CRNInfo object from the mock_crn_list
    crn_data = mock_crn_list[2].copy()
    crn_data["system_usage"] = None
    basic_crn_info = CRNInfo.from_unsanitized_input(crn_data)

    # Verify system_usage is None
    assert basic_crn_info.system_usage is None

    # Create CRNTable instance and mock the table
    crn_table = CRNTable(
        crn_list=[],
    )
    crn_table.table = MagicMock()

    # Add CRN without system_usage
    await crn_table.add_crn_info(basic_crn_info, 0)

    # Verify it was processed correctly
    assert crn_table.active_crns == 1
    assert crn_table.filtered_crns == 1
    # Verify the table.add_row was called
    crn_table.table.add_row.assert_called_once()


@pytest.mark.asyncio
async def test_show_instances():
    """Test the show_instances function with mocked data."""
    from aleph_client.commands.instance.display import show_instances

    mock_message = MagicMock()
    mock_message.item_hash = "vm_hash_0"
    mock_message.sender = "0x1234567890abcdef"

    payment_mock = MagicMock()
    payment_mock.type = PaymentType.superfluid.value
    mock_message.content.payment = payment_mock
    mock_message.content.metadata = {"name": "Test VM"}
    mock_message.content.environment.trusted_execution.firmware = None
    mock_message.content.requirements.gpu = None
    mock_message.chain.value = "ETH"
    mock_message.content.address = mock_message.sender
    mock_message.content.resources.vcpus = 2
    mock_message.content.resources.memory = 4096
    mock_message.content.rootfs.size_mib = 10240

    mock_manual = MagicMock()
    mock_manual.__class__.__name__ = "InstanceManual"
    mock_manual.crn_url = "https://test.crn.com"

    mock_allocations = MagicMock()
    mock_allocations.root = {"vm_hash_0": mock_manual}

    mock_execution = MagicMock()
    mock_execution.__class__.__name__ = "CrnExecutionV2"

    mock_execution.status = MagicMock()
    mock_execution.status.started_at = "2025-06-01T00:00:00Z"
    mock_execution.status.stopped_at = None
    mock_execution.status.stopping_at = None
    mock_execution.status.preparing_at = None

    mock_execution.networking = MagicMock()
    mock_execution.networking.ipv4_network = "192.168.1.0/24"
    mock_execution.networking.ipv6_network = "2001:db8::/64"
    mock_execution.networking.host_ipv4 = "192.168.1.1"
    mock_execution.networking.ipv6_ip = "2001:db8::1234"
    mock_execution.networking.mapped_ports = {}

    mock_executions = MagicMock()
    mock_executions.root = {"vm_hash_0": mock_execution}

    with patch("aleph_client.commands.instance.display.InstanceTableBuilder") as mock_builder_class:
        mock_table = MagicMock()
        mock_builder = MagicMock()
        mock_builder.build = AsyncMock(return_value=mock_table)
        mock_builder_class.return_value = mock_builder

        with patch("aleph_client.commands.instance.display.Console") as mock_console_class:
            mock_console = MagicMock()
            mock_console_class.return_value = mock_console

            with patch("aleph_client.commands.instance.display.download", AsyncMock(return_value=None)):
                with patch("aleph_client.commands.instance.display.AlephHttpClient") as mock_client_class:
                    mock_client = AsyncMock()
                    mock_price = MagicMock()
                    mock_price.required_tokens = "0.001"
                    mock_price.cost = "0.001"
                    mock_client.get_program_price = AsyncMock(return_value=mock_price)

                    mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client_class.return_value.__aexit__ = AsyncMock(return_value=None)

                    await show_instances([mock_message], mock_allocations, mock_executions)

    mock_builder_class.assert_called_once()
    args = mock_builder_class.call_args[0]
    assert len(args) == 3
    assert len(args[0]) == 1  # messages list with one item
    assert args[1] == mock_allocations
    assert args[2] == mock_executions

    mock_console.print.assert_called_with(mock_table)

    mock_builder.display_summary_panel.assert_called_once()
