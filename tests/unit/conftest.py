"""
    Dummy conftest.py for aleph_client.

    If you don't know what this is for, just leave it empty.
    Read more about conftest.py under:
    https://pytest.org/latest/plugins.html
"""

import hashlib
import json
import time
from collections.abc import Generator
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from tempfile import NamedTemporaryFile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aleph.sdk.chains.common import generate_key
from aleph.sdk.chains.ethereum import ETHAccount, get_fallback_private_key
from aleph.sdk.client.services.crn import CrnList
from aleph.sdk.client.services.pricing import PricingModel
from aleph.sdk.client.services.settings import NetworkSettingsModel
from aleph.sdk.query.responses import BalanceResponse
from aleph.sdk.types import StoredContent, Voucher, VoucherAttribute
from aleph_message.models import Chain, ItemHash, ItemType, StoreContent, StoreMessage
from aleph_message.models.base import MessageType

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
    FAKE_STORE_HASH,
)

# Constants for voucher testing
MOCK_ADDRESS = "0x1234567890123456789012345678901234567890"
MOCK_SOLANA_ADDRESS = "abcdefghijklmnopqrstuvwxyz123456789"
MOCK_METADATA_ID = "metadata123"
MOCK_VOUCHER_ID = "voucher123"


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
def mock_crn_list_obj(mock_crn_list):
    """
    Wrap the raw mock_crn_list data into a CrnList object,
    same type as call_program_crn_list() would return.
    """
    return CrnList.from_api({"crns": mock_crn_list})


@pytest.fixture
def mock_crn_info(mock_crn_list):
    """Create a mock CRNInfo object."""
    return CRNInfo.from_unsanitized_input(mock_crn_list[0])


@pytest.fixture
def mock_pricing_info_response():
    pricing_file = Path(__file__).parent / "mock_data/pricing_data.json"
    with open(pricing_file) as f:
        pricing_data = json.load(f)

    pricing_model = PricingModel(pricing_data["data"]["pricing"])

    return pricing_model


@pytest.fixture
def mock_settings_info():
    settings_file = Path(__file__).parent / "mock_data/settings_aggregate.json"
    with open(settings_file) as f:
        settings_data = json.load(f)

    # Create a proper NetworkSettingsModel using the settings data
    return NetworkSettingsModel(
        compatible_gpus=settings_data["data"]["settings"].get("compatible_gpus", []),
        community_wallet_address=settings_data["data"]["settings"].get(
            "community_wallet_address", "0x5aBd3258C5492fD378EBC2e0017416E199e5Da56"
        ),
        community_wallet_timestamp=settings_data["data"]["settings"].get("community_wallet_timestamp", 1739996239),
        last_crn_version="0.0.0",  # Add missing required field for tests
    )


@pytest.fixture
def mock_store_message_upload_fixture():
    return {
        "sender": "0xe0aaF578B287de16852dbc54Ae34a263FF2F4b9E",
        "chain": "ETH",
        "signature": (
            "0xe2d0bd0476e73652b1dbac082f250387b0a7691ee19f39ad6ffce2e8a45028160f3e35ef346beb4a4b5f50"
            "aacdd0d9b454f63eeedc3f8058eb25f7b096eadd231c"
        ),
        "type": "STORE",
        "item_content": (
            '{"item_type":"storage","item_hash":"QmTestHashForMockedUpload","ref":null,'
            '"address":"0xe0aaF578B287de16852dbc54Ae34a263FF2F4b9E","time":1738837907}'
        ),
        "item_type": "inline",
        "item_hash": "5b868dc8c2df0dd9bb810b7a31cc50c8ad1e6569905e45ab4fd2eee36fecc4d2",
        "time": 1738837907,
        "channel": "test-chan-1",
        "content": {
            "address": "0xe0aaF578B287de16852dbc54Ae34a263FF2F4b9E",
            "time": 1738837907,
            "item_type": "storage",
            "item_hash": "QmTestHashForMockedUpload",
            "size": 12,
            "content_type": "text/plain",
            "ref": None,
            "metadata": None,
        },
    }


@pytest.fixture
def mock_upload_store(mocker, store_message_fixture):
    """Create a mock for the AuthenticatedAlephHttpClient.create_store method."""
    from aleph_message.models import StoreMessage

    message = StoreMessage.model_validate(store_message_fixture)
    return mocker.patch("aleph.sdk.AuthenticatedAlephHttpClient.create_store", return_value=[message, "processed"])


@pytest.fixture
def mock_api_response(mock_pricing_info_response, mock_settings_info):
    """
    Side-effect function for ClientSession.get that returns the right mocked response
    depending on the URL. It is a SYNC callable returning an async context manager.
    """

    def side_effect(url, *args, **kwargs):
        if "keys=pricing" in url:
            return mock_pricing_info_response
        if "keys=settings" in url:
            return mock_settings_info

    return side_effect


@pytest.fixture
def mock_authenticated_aleph_http_client():
    with patch("aleph_client.commands.files.AuthenticatedAlephHttpClient", autospec=True) as mock_client:
        instance = mock_client.return_value
        instance.__aenter__.return_value = instance
        instance.__aexit__.return_value = None

        # Build a real account so we can reuse its address
        pkey = get_fallback_private_key()
        account = ETHAccount(private_key=pkey)
        instance.account = account

        async def create_store(file_content, *args, **kwargs):
            file_hash = hashlib.sha256(file_content).hexdigest()

            sender = account.get_address()
            content = StoreContent(
                item_type=ItemType("storage"),
                item_hash=ItemHash(file_hash),
                address=sender,
                time=time.time(),
            )

            msg = StoreMessage(
                type=MessageType.store,
                sender=sender,
                chain=Chain.ETH,
                channel="test",
                content=content,
                signature="ababababab",
                item_hash=ItemHash(file_hash),
                time=datetime.now(tz=timezone.utc),
                item_type=ItemType.storage,
            )
            status = {"status": "success"}
            return msg, status

        instance.create_store = AsyncMock(side_effect=create_store)

        yield mock_client


@pytest.fixture
def mock_aleph_http_client():
    """Create a mock for the AlephHttpClient class."""
    with patch("aleph_client.commands.files.AlephHttpClient", autospec=True) as mock_client:
        instance = mock_client.return_value
        instance.__aenter__.return_value = instance
        instance.__aexit__.return_value = None

        # Mock download_file_to_buffer
        async def mock_download_file(*args, **kwargs):
            # Just create a dummy file content
            return b"Test file content"

        instance.download_file_to_buffer = AsyncMock(side_effect=mock_download_file)
        instance.download_file_ipfs_to_buffer = AsyncMock(side_effect=mock_download_file)

        # Mock get_stored_content
        async def mock_get_stored_content(item_hash, *args, **kwargs):
            return StoredContent(
                hash=item_hash,
                filename=f"{item_hash}.txt",
                url=f"https://api.aleph.im/storage/{item_hash}",
            )

        instance.get_stored_content = AsyncMock(side_effect=mock_get_stored_content)

        yield mock_client


@pytest.fixture
def mock_aiohttp_client_session():
    """Create a mock for the aiohttp.ClientSession."""
    with patch("aiohttp.ClientSession") as mock_session:
        instance = mock_session.return_value
        instance.__aenter__.return_value = instance
        instance.__aexit__.return_value = None

        # Create a mock response
        mock_response = AsyncMock()
        mock_response.status = 200

        # Create example file listing data
        files_data = {
            "files": [
                {
                    "file_hash": "QmeomffUNfmQy76CQGy9NdmqEnnHU9soCexBnGU3ezPHVH",
                    "size": "1024",
                    "type": "file",
                    "created": "2025-08-01T12:00:00.000000+00:00",
                    "item_hash": FAKE_STORE_HASH,
                }
            ],
            "pagination_page": 1,
            "pagination_total": 1,
            "pagination_per_page": 100,
            "address": "0xe0aaF578B287de16852dbc54Ae34a263FF2F4b9E",
            "total_size": "1024",
        }

        async def mock_json():
            return files_data

        mock_response.json = AsyncMock(side_effect=mock_json)
        instance.get = AsyncMock(return_value=mock_response)

        yield mock_session


@pytest.fixture
def mock_vouchers():
    """Create mock vouchers for testing."""
    # Create EVM voucher
    evm_voucher = Voucher(
        id=MOCK_VOUCHER_ID,
        metadata_id=MOCK_METADATA_ID,
        name="EVM Test Voucher",
        description="A test voucher for EVM chains",
        external_url="https://example.com",
        image="https://example.com/image.png",
        icon="https://example.com/icon.png",
        attributes=[
            VoucherAttribute(trait_type="Duration", value="30 days", display_type="string"),
            VoucherAttribute(trait_type="Compute Units", value="4", display_type="number"),
            VoucherAttribute(trait_type="Type", value="instance", display_type="string"),
        ],
    )

    # Create Solana voucher
    solana_voucher = Voucher(
        id="solticket123",
        metadata_id=MOCK_METADATA_ID,
        name="Solana Test Voucher",
        description="A test voucher for Solana",
        external_url="https://example.com",
        image="https://example.com/image.png",
        icon="https://example.com/icon.png",
        attributes=[
            VoucherAttribute(trait_type="Duration", value="60 days", display_type="string"),
            VoucherAttribute(trait_type="Compute Units", value="8", display_type="number"),
            VoucherAttribute(trait_type="Type", value="instance", display_type="string"),
        ],
    )

    return evm_voucher, solana_voucher


@pytest.fixture
def mock_voucher_service(mock_vouchers):
    """Create a mock voucher service with pre-configured responses."""
    evm_voucher, solana_voucher = mock_vouchers

    mock_service = MagicMock()
    mock_service.fetch_vouchers_by_chain = AsyncMock(return_value=[evm_voucher])
    mock_service.get_vouchers = AsyncMock(return_value=[evm_voucher, solana_voucher])
    mock_service.get_evm_vouchers = AsyncMock(return_value=[evm_voucher])
    mock_service.get_solana_vouchers = AsyncMock(return_value=[solana_voucher])

    return mock_service


@pytest.fixture
def mock_voucher_empty():
    """Create a mock voucher service with pre-configured responses."""
    mock_service = MagicMock()
    mock_service.fetch_vouchers_by_chain = AsyncMock(return_value=[])
    mock_service.get_vouchers = AsyncMock(return_value=[])
    mock_service.get_evm_vouchers = AsyncMock(return_value=[])
    mock_service.get_solana_vouchers = AsyncMock(return_value=[])

    return mock_service


@pytest.fixture
def mock_get_balances():
    # Create a proper BalanceResponse with all Decimal values
    response = BalanceResponse(
        address="0xCAfEcAfeCAfECaFeCaFecaFecaFECafECafeCaFe",
        balance=Decimal(24853),
        details={"AVAX": Decimal(4000), "BASE": Decimal(10000), "ETH": Decimal(10853)},
        locked_amount=Decimal("4663.334518051392"),
        credit_balance=5000,
    )
    return response
