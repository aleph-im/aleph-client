import asyncio
from datetime import datetime, timezone
from typing import Set
from unittest import mock

import pytest
from aiohttp import InvalidURL
from aleph_message.models.execution.environment import CpuProperties
from multidict import CIMultiDict, CIMultiDictProxy

from aleph_client.commands.instance.display import (
    ProgressTable,
    create_table_with_progress_bar,
    update_table,
)
from aleph_client.commands.instance.network import (
    FORBIDDEN_HOSTS,
    MachineInfoQueue,
    fetch_crn_info,
    get_version,
    sanitize_url,
)
from aleph_client.models import (
    CoreFrequencies,
    CpuUsage,
    DiskUsage,
    LoadAverage,
    MachineInfo,
    MachineProperties,
    MachineUsage,
    MemoryUsage,
    UsagePeriod,
)


def dummy_machine_info() -> MachineInfo:
    """Create a dummy MachineInfo object for testing purposes."""
    return MachineInfo(
        machine_usage=MachineUsage(
            cpu=CpuUsage(
                count=8,
                load_average=LoadAverage(load1=0.5, load5=0.4, load15=0.3),
                core_frequencies=CoreFrequencies(min=1.0, max=2.0),
            ),
            mem=MemoryUsage(
                total_kB=1_000_000,
                available_kB=500_000,
            ),
            disk=DiskUsage(
                total_kB=1_000_000,
                available_kB=500_000,
            ),
            period=UsagePeriod(
                start_timestamp=datetime.now(tz=timezone.utc),
                duration_seconds=60,
            ),
            properties=MachineProperties(
                cpu=CpuProperties(
                    architecture="x86_64",
                    vendor="AuthenticAMD",
                ),
            ),
        ),
        score=0.5,
        name="CRN",
        version="0.0.1",
        reward_address="0xcafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe",
        url="https://example.com",
    )


def dict_to_ci_multi_dict_proxy(d: dict) -> CIMultiDictProxy:
    """Return a read-only proxy to a case-insensitive multi-dict created from a dict."""
    return CIMultiDictProxy(CIMultiDict(d))


def test_get_version() -> None:

    # No server field in headers
    headers = dict_to_ci_multi_dict_proxy({})
    assert get_version(headers) is None

    # Server header but no aleph-vm
    headers = dict_to_ci_multi_dict_proxy({"Server": "nginx"})
    assert get_version(headers) is None

    # Server header with aleph-vm
    headers = dict_to_ci_multi_dict_proxy({"Server": "aleph-vm/0.1.0"})
    assert get_version(headers) == "0.1.0"

    # Server header multiple aleph-vm values
    headers = dict_to_ci_multi_dict_proxy(
        {"Server": "aleph-vm/0.1.0", "server": "aleph-vm/0.2.0"}
    )
    assert get_version(headers) == "0.1.0"


def test_create_table_with_progress_bar():
    """Test the creation of a table with progress bar."""
    sized_object = [1, 2, 3]
    table, increment_function = create_table_with_progress_bar(sized_object)
    assert isinstance(table, ProgressTable)

    # Test that calling the increment function ends up with the progress bar
    # being finished after `len(sized_objects)` calls.
    for i in range(3):
        # The progress bar should not be finished yet
        assert table.progress.tasks[0].finished_time is None
        increment_function()

    # The progress bar should be finished now
    finished_time = table.progress.tasks[0].finished_time
    assert finished_time is not None and finished_time > 0


@pytest.mark.asyncio
async def test_update_table():
    queue: MachineInfoQueue = asyncio.Queue()
    table = mock.Mock()
    table.add_row = mock.Mock()
    increment_progress_bar = mock.Mock()
    valid_reward_addresses: Set[str] = set()

    async def populate_queue():
        assert table.add_row.call_count == 0
        # Put the data in the queue
        await queue.put(dummy_machine_info())
        # End the test by putting an end of queue marker
        await queue.put("END_OF_QUEUE")

    # Populate the queue and update the table concurrently.
    await asyncio.gather(
        populate_queue(),
        update_table(queue, table, increment_progress_bar, valid_reward_addresses),
    )

    assert table.add_row.call_count == 1
    assert valid_reward_addresses == {dummy_machine_info().reward_address}


@pytest.mark.asyncio
async def test_fetch_crn_info() -> None:
    # Test with valid node
    # TODO: Mock the response from the node, don't rely on a real node
    node_url = "https://ovh.staging.aleph.sh"
    machine_usage, version = await fetch_crn_info(node_url)
    assert machine_usage is not None
    assert version is not None
    assert isinstance(machine_usage, MachineUsage)
    assert isinstance(version, str)

    # Test with invalid node
    invalid_node_url = "https://coconut.example.org/"
    assert await fetch_crn_info(invalid_node_url) == (None, None)

    # TODO: Test different error handling


def test_sanitize_url_with_empty_url():
    with pytest.raises(InvalidURL, match="Empty URL"):
        sanitize_url("")


def test_sanitize_url_with_invalid_scheme():
    with pytest.raises(InvalidURL, match="Invalid URL scheme"):
        sanitize_url("ftp://example.org")


def test_sanitize_url_with_forbidden_host():
    for host in FORBIDDEN_HOSTS:
        with pytest.raises(InvalidURL, match="Invalid URL host"):
            sanitize_url(f"http://{host}")


def test_sanitize_url_with_valid_url():
    url = "http://example.org"
    assert sanitize_url(url) == url


def test_sanitize_url_with_https_scheme():
    url = "https://example.org"
    assert sanitize_url(url) == url
