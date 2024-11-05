from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import cast
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import InvalidURL
from aleph.sdk.chains.ethereum import ETHAccount
from aleph_message.models import Chain
from aleph_message.models.execution.base import Payment, PaymentType
from aleph_message.models.execution.environment import CpuProperties
from eth_utils.currency import to_wei
from multidict import CIMultiDict, CIMultiDictProxy
from utils import sanitize_url

from aleph_client.commands.instance import delete
from aleph_client.commands.instance.network import FORBIDDEN_HOSTS, fetch_crn_info
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
        hash="blalba",
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


@pytest.mark.asyncio
async def test_fetch_crn_info() -> None:
    # Test with valid node
    # TODO: Mock the response from the node, don't rely on a real node
    node_url = "https://ovh.staging.aleph.sh"
    info = await fetch_crn_info(node_url)
    assert info
    assert info["machine_usage"]

    # Test with invalid node
    invalid_node_url = "https://coconut.example.org/"
    assert not (await fetch_crn_info(invalid_node_url))

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


class MockETHAccount(ETHAccount):
    pass


def create_test_account() -> MockETHAccount:
    return MockETHAccount(private_key=b"deca" * 8)


@pytest.mark.asyncio
async def test_delete_instance():
    item_hash = "cafe" * 16
    test_account = create_test_account()

    # Mocking get_flow and delete_flow methods using patch.object
    with patch.object(test_account, "get_flow", AsyncMock(return_value={"flowRate": to_wei(123, unit="ether")})):
        delete_flow_mock = AsyncMock()
        with patch.object(test_account, "delete_flow", delete_flow_mock):
            mock_response_message = MagicMock(
                sender=test_account.get_address(),
                content=MagicMock(
                    payment=Payment(
                        chain=Chain.AVAX,
                        type=PaymentType.superfluid,
                        receiver=ETHAccount(private_key=b"cafe" * 8).get_address(),
                    )
                ),
            )

            mock_client = AsyncMock(
                get_message=AsyncMock(return_value=mock_response_message),
                get_program_price=AsyncMock(return_value=MagicMock(required_tokens=123)),
                forget=AsyncMock(return_value=(MagicMock(), MagicMock())),
            )

            mock_client_class = MagicMock()
            mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)

            mock_load_account = MagicMock(return_value=test_account)

            with patch("aleph_client.commands.instance.AuthenticatedAlephHttpClient", mock_client_class):
                with patch("aleph_client.commands.instance._load_account", mock_load_account):
                    await delete(item_hash)

                    # The flow has been deleted since payment uses Superfluid and there is only one flow mocked
                    delete_flow_mock.assert_awaited_once()

                    # The message has been forgotten
                    mock_client.forget.assert_called_once()
