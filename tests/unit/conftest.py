"""
    Dummy conftest.py for aleph_client.

    If you don't know what this is for, just leave it empty.
    Read more about conftest.py under:
    https://pytest.org/latest/plugins.html
"""

import json
from collections.abc import Generator
from pathlib import Path
from tempfile import NamedTemporaryFile
from unittest.mock import AsyncMock

import pytest
from aleph.sdk.chains.common import generate_key

from aleph_client.models import CRNInfo

from .mocks import (
    FAKE_CRN_BASIC_ADDRESS,
    FAKE_CRN_BASIC_HASH,
    FAKE_CRN_BASIC_URL,
    FAKE_CRN_CONF_ADDRESS,
    FAKE_CRN_CONF_HASH,
    FAKE_CRN_CONF_URL,
    FAKE_CRN_GPU_ADDRESS,
    FAKE_CRN_GPU_HASH,
    FAKE_CRN_GPU_URL,
)


@pytest.fixture
def new_config_file() -> Generator[Path, None, None]:
    with NamedTemporaryFile(suffix=".json") as config_file:
        yield Path(config_file.name)


@pytest.fixture
def empty_account_file() -> Generator[Path, None, None]:
    with NamedTemporaryFile(suffix=".key") as key_file:
        yield Path(key_file.name)


@pytest.fixture
def env_files(new_config_file: Path, empty_account_file: Path) -> Generator[tuple[Path, Path], None, None]:
    new_config_file.write_text(f'{{"path": "{empty_account_file}", "chain": "ETH"}}')
    empty_account_file.write_bytes(generate_key())
    yield empty_account_file, new_config_file


@pytest.fixture
def mock_crn_list():
    """Create a mock CRN list for testing."""
    return [
        {
            "hash": FAKE_CRN_GPU_HASH,
            "name": "Test GPU Instance",
            "time": 1739525120.505,
            "type": "compute",
            "owner": FAKE_CRN_GPU_ADDRESS,
            "score": 0.964502797686815,
            "banner": "",
            "locked": True,
            "parent": FAKE_CRN_GPU_HASH,
            "reward": FAKE_CRN_GPU_ADDRESS,
            "status": "linked",
            "address": FAKE_CRN_GPU_URL,
            "manager": "",
            "picture": "",
            "authorized": "",
            "description": "",
            "performance": 0,
            "multiaddress": "",
            "score_updated": True,
            "stream_reward": FAKE_CRN_GPU_ADDRESS,
            "inactive_since": None,
            "decentralization": 0.852680607762069,
            "registration_url": "",
            "terms_and_conditions": "",
            "config_from_crn": True,
            "debug_config_from_crn_at": "2025-06-18T12:09:03.843059+00:00",
            "debug_config_from_crn_error": "None",
            "debug_usage_from_crn_at": "2025-06-18T12:09:03.843059+00:00",
            "usage_from_crn_error": "None",
            "version": "1.6.0-rc1",
            "payment_receiver_address": FAKE_CRN_GPU_ADDRESS,
            "gpu_support": True,
            "confidential_support": False,
            "qemu_support": True,
            "system_usage": {
                "cpu": {
                    "count": 20,
                    "load_average": {"load1": 0.357421875, "load5": 0.31982421875, "load15": 0.34912109375},
                    "core_frequencies": {"min": 800, "max": 4280},
                },
                "mem": {"total_kB": 67219530, "available_kB": 61972037},
                "disk": {"total_kB": 1853812338, "available_kB": 1320664518},
                "period": {"start_timestamp": "2025-06-18T12:09:00Z", "duration_seconds": 60},
                "properties": {"cpu": {"architecture": "x86_64", "vendor": "GenuineIntel", "features": []}},
                "gpu": {
                    "devices": [
                        {
                            "vendor": "NVIDIA",
                            "model": "RTX 4000 ADA",
                            "device_name": "AD104GL [RTX 4000 SFF Ada Generation]",
                            "device_class": "0300",
                            "pci_host": "01:00.0",
                            "device_id": "10de:27b0",
                            "compatible": True,
                        }
                    ],
                    "available_devices": [
                        {
                            "vendor": "NVIDIA",
                            "model": "RTX 4000 ADA",
                            "device_name": "AD104GL [RTX 4000 SFF Ada Generation]",
                            "device_class": "0300",
                            "pci_host": "01:00.0",
                            "device_id": "10de:27b0",
                            "compatible": True,
                        }
                    ],
                },
                "active": True,
            },
            "compatible_gpus": [
                {
                    "vendor": "NVIDIA",
                    "model": "RTX 4000 ADA",
                    "device_name": "AD104GL [RTX 4000 SFF Ada Generation]",
                    "device_class": "0300",
                    "pci_host": "01:00.0",
                    "device_id": "10de:27b0",
                    "compatible": True,
                }
            ],
            "compatible_available_gpus": [
                {
                    "vendor": "NVIDIA",
                    "model": "RTX 4000 ADA",
                    "device_name": "AD104GL [RTX 4000 SFF Ada Generation]",
                    "device_class": "0300",
                    "pci_host": "01:00.0",
                    "device_id": "10de:27b0",
                    "compatible": True,
                }
            ],
            "ipv6_check": {"host": True, "vm": True},
        },
        {
            "hash": FAKE_CRN_CONF_HASH,
            "name": "Test Conf CRN",
            "time": 1739296606.021,
            "type": "compute",
            "owner": FAKE_CRN_CONF_ADDRESS,
            "score": 0.964334395009276,
            "banner": "",
            "locked": False,
            "parent": FAKE_CRN_CONF_HASH,
            "reward": FAKE_CRN_CONF_ADDRESS,
            "status": "linked",
            "address": FAKE_CRN_CONF_URL,
            "manager": "",
            "picture": "",
            "authorized": "",
            "description": "",
            "performance": 0,
            "multiaddress": "",
            "score_updated": False,
            "stream_reward": FAKE_CRN_CONF_ADDRESS,
            "inactive_since": None,
            "decentralization": 0.994724704221032,
            "registration_url": "",
            "terms_and_conditions": "",
            "config_from_crn": False,
            "debug_config_from_crn_at": "2025-06-18T12:09:03.951298+00:00",
            "debug_config_from_crn_error": "None",
            "debug_usage_from_crn_at": "2025-06-18T12:09:03.951298+00:00",
            "usage_from_crn_error": "None",
            "version": "1.5.1",
            "payment_receiver_address": FAKE_CRN_CONF_ADDRESS,
            "gpu_support": False,
            "confidential_support": True,
            "qemu_support": True,
            "system_usage": {
                "cpu": {
                    "count": 224,
                    "load_average": {"load1": 3.8466796875, "load5": 3.9228515625, "load15": 3.82080078125},
                    "core_frequencies": {"min": 1500, "max": 2200},
                },
                "mem": {"total_kB": 807728145, "available_kB": 630166945},
                "disk": {"total_kB": 14971880235, "available_kB": 152975388},
                "period": {"start_timestamp": "2025-06-18T12:09:00Z", "duration_seconds": 60},
                "properties": {
                    "cpu": {"architecture": "x86_64", "vendor": "AuthenticAMD", "features": ["sev", "sev_es"]}
                },
                "gpu": {"devices": [], "available_devices": []},
                "active": True,
            },
            "compatible_gpus": [],
            "compatible_available_gpus": [],
            "ipv6_check": {"host": True, "vm": True},
        },
        {
            "hash": FAKE_CRN_BASIC_HASH,
            "name": "Test Basic CRN",
            "time": 1687179700.242,
            "type": "compute",
            "owner": FAKE_CRN_BASIC_ADDRESS,
            "score": 0.979808976368904,
            "banner": FAKE_CRN_BASIC_HASH,
            "locked": False,
            "parent": FAKE_CRN_BASIC_HASH,
            "reward": FAKE_CRN_BASIC_ADDRESS,
            "status": "linked",
            "address": FAKE_CRN_BASIC_URL,
            "manager": FAKE_CRN_BASIC_ADDRESS,
            "picture": FAKE_CRN_BASIC_HASH,
            "authorized": "",
            "description": "",
            "performance": 0,
            "multiaddress": "",
            "score_updated": True,
            "stream_reward": FAKE_CRN_BASIC_ADDRESS,
            "inactive_since": None,
            "decentralization": 0.93953628188216,
            "registration_url": "",
            "terms_and_conditions": "",
            "config_from_crn": True,
            "debug_config_from_crn_at": "2025-06-18T12:08:59.599676+00:00",
            "debug_config_from_crn_error": "None",
            "debug_usage_from_crn_at": "2025-06-18T12:08:59.599676+00:00",
            "usage_from_crn_error": "None",
            "version": "1.5.1",
            "payment_receiver_address": FAKE_CRN_BASIC_ADDRESS,
            "gpu_support": False,
            "confidential_support": False,
            "qemu_support": True,
            "system_usage": {
                "cpu": {
                    "count": 32,
                    "load_average": {"load1": 0, "load5": 0.01513671875, "load15": 0},
                    "core_frequencies": {"min": 1200, "max": 3400},
                },
                "mem": {"total_kB": 270358832, "available_kB": 266152607},
                "disk": {"total_kB": 1005067972, "available_kB": 919488466},
                "period": {"start_timestamp": "2025-06-18T12:09:00Z", "duration_seconds": 60},
                "properties": {"cpu": {"architecture": "x86_64", "vendor": "GenuineIntel", "features": []}},
                "gpu": {"devices": [], "available_devices": []},
                "active": True,
            },
            "compatible_gpus": [],
            "compatible_available_gpus": [],
            "ipv6_check": {"host": True, "vm": False},
        },
    ]


@pytest.fixture
def mock_crn_info(mock_crn_list):
    """Create a mock CRNInfo object."""
    return CRNInfo.from_unsanitized_input(mock_crn_list[0])


@pytest.fixture
def mock_pricing_info_response():
    pricing_file = Path(__file__).parent / "pricing_data.json"
    with open(pricing_file) as f:
        pricing_data = json.load(f)

    # Create a mock response for the HTTP get call
    mock_response = AsyncMock()
    mock_response.__aenter__.return_value = mock_response
    mock_response.status = 200
    mock_response.json = AsyncMock(return_value=pricing_data)

    return mock_response
