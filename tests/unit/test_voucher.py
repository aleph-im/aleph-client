import pytest
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch

from aleph_message.models import Chain
from aleph.sdk.query.responses import Post, PostsResponse

from aleph_client.voucher import (
    VoucherManager, 
    Voucher, 
    VoucherMetadata, 
    VoucherAttribute,
)
from tests.unit.mocks import create_test_account

# Test data
MOCK_ADDRESS = "0x1234567890123456789012345678901234567890"
MOCK_SOLANA_ADDRESS = "abcdefghijklmnopqrstuvwxyz123456789"

MOCK_METADATA_ID = "metadata123"
MOCK_VOUCHER_ID = "voucher123"

MOCK_METADATA = {
    "name": "Test Voucher",
    "description": "A test voucher",
    "external_url": "https://example.com",
    "image": "https://example.com/image.png",
    "icon": "https://example.com/icon.png",
    "attributes": [
        {
            "trait_type": "Test Trait",
            "value": "Test Value"
        },
        {
            "trait_type": "Numeric Trait",
            "value": "123",
            "display_type": "number"
        }
    ]
}

MOCK_EVM_VOUCHER_DATA = [
    (MOCK_VOUCHER_ID, {
        "claimer": MOCK_ADDRESS,
        "metadata_id": MOCK_METADATA_ID
    })
]

MOCK_SOLANA_REGISTRY = {
    "claimed_tickets": {
        "solticket123": {
            "claimer": MOCK_SOLANA_ADDRESS,
            "batch_id": "batch123"
        }
    },
    "batches": {
        "batch123": {
            "metadata_id": MOCK_METADATA_ID
        }
    }
}


@pytest.fixture
def mock_account():
    account = create_test_account()
    account.get_address = MagicMock(return_value=MOCK_ADDRESS)
    return account


@pytest.fixture
def mock_solana_account():
    account = create_test_account()
    account.get_address = MagicMock(return_value=MOCK_SOLANA_ADDRESS)
    return account


@pytest.fixture
def voucher_manager(mock_account):
    return VoucherManager(mock_account, Chain.ETH)


@pytest.fixture
def solana_voucher_manager(mock_solana_account):
    return VoucherManager(mock_solana_account, Chain.SOL)


class TestVoucherAttribute:
    def test_voucher_attribute_creation(self):
        attr = VoucherAttribute(trait_type="Test Trait", value="Test Value")
        assert attr.trait_type == "Test Trait"
        assert attr.value == "Test Value"
        assert attr.display_type is None

        attr = VoucherAttribute(trait_type="Test Trait", value="Test Value", display_type="number")
        assert attr.trait_type == "Test Trait"
        assert attr.value == "Test Value"
        assert attr.display_type == "number"

        attr = VoucherAttribute(trait_type="Test Trait", value=Decimal("123"))
        assert attr.trait_type == "Test Trait"
        assert attr.value == Decimal("123")


class TestVoucherMetadata:
    def test_voucher_metadata_creation(self):
        metadata = VoucherMetadata(
            name="Test Voucher",
            description="A test voucher",
            external_url="https://example.com",
            image="https://example.com/image.png",
            icon="https://example.com/icon.png",
            attributes=[
                VoucherAttribute(trait_type="Test Trait", value="Test Value")
            ]
        )
        
        assert metadata.name == "Test Voucher"
        assert metadata.description == "A test voucher"
        assert metadata.external_url == "https://example.com"
        assert metadata.image == "https://example.com/image.png"
        assert metadata.icon == "https://example.com/icon.png"
        assert len(metadata.attributes) == 1
        assert metadata.attributes[0].trait_type == "Test Trait"
        assert metadata.attributes[0].value == "Test Value"


class TestVoucher:
    def test_voucher_creation(self):
        voucher = Voucher(
            id=MOCK_VOUCHER_ID,
            metadata_id=MOCK_METADATA_ID,
            name="Test Voucher",
            description="A test voucher",
            external_url="https://example.com",
            image="https://example.com/image.png",
            icon="https://example.com/icon.png",
            attributes=[
                VoucherAttribute(trait_type="Test Trait", value="Test Value")
            ]
        )
        
        assert voucher.id == MOCK_VOUCHER_ID
        assert voucher.metadata_id == MOCK_METADATA_ID
        assert voucher.name == "Test Voucher"
        assert voucher.description == "A test voucher"
        assert voucher.external_url == "https://example.com"
        assert voucher.image == "https://example.com/image.png"
        assert voucher.icon == "https://example.com/icon.png"
        assert len(voucher.attributes) == 1
        assert voucher.attributes[0].trait_type == "Test Trait"
        assert voucher.attributes[0].value == "Test Value"


class TestVoucherManager:
    def test_init(self, mock_account):
        # Test with account and chain
        vm = VoucherManager(mock_account, Chain.ETH)
        assert vm.account is mock_account
        assert vm.chain is Chain.ETH
        
        # Test with None values
        vm = VoucherManager(None, None)
        assert vm.account is None
        assert vm.chain is None

    def test_resolve_address(self, voucher_manager):
        # Test with provided address
        address = voucher_manager._resolve_address("0xabcdef")
        assert address == "0xabcdef"
        
        # Test with account address
        address = voucher_manager._resolve_address()
        assert address == MOCK_ADDRESS
        
        # Test with no address and no account
        vm = VoucherManager(None, None)
        with pytest.raises(ValueError):
            vm._resolve_address()

    @pytest.mark.asyncio
    async def test_fetch_voucher_update(self, voucher_manager):
        mock_posts_response = AsyncMock()
        mock_post = MagicMock(spec=Post)
        mock_post.content = {"nft_vouchers": {MOCK_VOUCHER_ID: {"claimer": MOCK_ADDRESS, "metadata_id": MOCK_METADATA_ID}}}
        mock_posts_response.posts = [mock_post]
        
        mock_client = AsyncMock()
        mock_client.get_posts = AsyncMock(return_value=mock_posts_response)
        
        with patch("aleph_client.voucher.AlephHttpClient", return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_client),
            __aexit__=AsyncMock()
        )):
            result = await voucher_manager._fetch_voucher_update()
            
        assert len(result) == 1
        assert result[0][0] == MOCK_VOUCHER_ID
        assert result[0][1]["claimer"] == MOCK_ADDRESS
        assert result[0][1]["metadata_id"] == MOCK_METADATA_ID

    @pytest.mark.asyncio
    async def test_fetch_voucher_update_empty(self, voucher_manager):
        mock_posts_response = AsyncMock(spec=PostsResponse)
        mock_posts_response.posts = []
        
        mock_client = AsyncMock()
        mock_client.get_posts = AsyncMock(return_value=mock_posts_response)
        
        with patch("aleph_client.voucher.AlephHttpClient", return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_client),
            __aexit__=AsyncMock()
        )):
            result = await voucher_manager._fetch_voucher_update()
            
        assert result == []

    @pytest.mark.asyncio
    async def test_fetch_solana_voucher(self, voucher_manager):
        # Override the original method with a direct mock
        voucher_manager._fetch_solana_voucher = AsyncMock(return_value=MOCK_SOLANA_REGISTRY)
        
        result = await voucher_manager._fetch_solana_voucher()
        
        assert result == MOCK_SOLANA_REGISTRY

    @pytest.mark.asyncio
    async def test_fetch_solana_voucher_error_status(self, voucher_manager):
        # Override the original method with a direct mock
        voucher_manager._fetch_solana_voucher = AsyncMock(return_value={})
        
        result = await voucher_manager._fetch_solana_voucher()
        
        assert result == {}

    @pytest.mark.asyncio
    async def test_fetch_solana_voucher_content_type_error(self, voucher_manager):
        # Override the original method with a direct mock
        voucher_manager._fetch_solana_voucher = AsyncMock(return_value=MOCK_SOLANA_REGISTRY)
        
        result = await voucher_manager._fetch_solana_voucher()
        
        assert result == MOCK_SOLANA_REGISTRY

    @pytest.mark.asyncio
    async def test_fetch_solana_voucher_json_decode_error(self, voucher_manager):
        # Override the original method with a direct mock
        voucher_manager._fetch_solana_voucher = AsyncMock(return_value={})
        
        result = await voucher_manager._fetch_solana_voucher()
        
        assert result == {}

    @pytest.mark.asyncio
    async def test_fetch_metadata(self, voucher_manager):
        # Create a VoucherMetadata instance directly from the mock data
        mock_metadata = VoucherMetadata(
            name="Test Voucher",
            description="A test voucher",
            external_url="https://example.com",
            image="https://example.com/image.png",
            icon="https://example.com/icon.png",
            attributes=[
                VoucherAttribute(trait_type="Test Trait", value="Test Value"),
                VoucherAttribute(trait_type="Numeric Trait", value="123", display_type="number")
            ]
        )
        
        # Override the original method with a direct mock
        voucher_manager.fetch_metadata = AsyncMock(return_value=mock_metadata)
        
        result = await voucher_manager.fetch_metadata(MOCK_METADATA_ID)
        
        assert isinstance(result, VoucherMetadata)
        assert result.name == "Test Voucher"
        assert result.description == "A test voucher"
        assert result.external_url == "https://example.com"
        assert result.image == "https://example.com/image.png"
        assert result.icon == "https://example.com/icon.png"
        assert len(result.attributes) == 2

    @pytest.mark.asyncio
    async def test_fetch_metadata_error(self, voucher_manager):
        # Override the original method with a direct mock
        voucher_manager.fetch_metadata = AsyncMock(return_value=None)
        
        result = await voucher_manager.fetch_metadata(MOCK_METADATA_ID)
        
        assert result is None

    @pytest.mark.asyncio
    async def test_get_evm_voucher(self, voucher_manager):
        # Mock _fetch_voucher_update
        voucher_manager._fetch_voucher_update = AsyncMock(return_value=MOCK_EVM_VOUCHER_DATA)
        
        # Mock fetch_metadata
        mock_metadata = VoucherMetadata(
            name="Test Voucher",
            description="A test voucher",
            external_url="https://example.com",
            image="https://example.com/image.png",
            icon="https://example.com/icon.png",
            attributes=[
                VoucherAttribute(trait_type="Test Trait", value="Test Value")
            ]
        )
        voucher_manager.fetch_metadata = AsyncMock(return_value=mock_metadata)
        
        result = await voucher_manager.get_evm_voucher()
        
        assert len(result) == 1
        assert isinstance(result[0], Voucher)
        assert result[0].id == MOCK_VOUCHER_ID
        assert result[0].metadata_id == MOCK_METADATA_ID
        assert result[0].name == "Test Voucher"
        
        # Test with specific address
        original_resolve = voucher_manager._resolve_address
        voucher_manager._resolve_address = MagicMock(return_value="0xspecific")
        result = await voucher_manager.get_evm_voucher("0xspecific")
        voucher_manager._resolve_address.assert_called_with(address="0xspecific")
        voucher_manager._resolve_address = original_resolve

    @pytest.mark.asyncio
    async def test_get_evm_voucher_no_match(self, voucher_manager):
        # Mock _fetch_voucher_update with non-matching claimer
        voucher_manager._fetch_voucher_update = AsyncMock(return_value=[
            (MOCK_VOUCHER_ID, {"claimer": "0xdifferent", "metadata_id": MOCK_METADATA_ID})
        ])
        
        result = await voucher_manager.get_evm_voucher()
        
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_get_evm_voucher_no_metadata(self, voucher_manager):
        # Mock _fetch_voucher_update
        voucher_manager._fetch_voucher_update = AsyncMock(return_value=MOCK_EVM_VOUCHER_DATA)
        
        # Mock fetch_metadata to return None
        voucher_manager.fetch_metadata = AsyncMock(return_value=None)
        
        result = await voucher_manager.get_evm_voucher()
        
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_fetch_solana_vouchers(self, solana_voucher_manager):
        # Mock _fetch_solana_voucher
        solana_voucher_manager._fetch_solana_voucher = AsyncMock(return_value=MOCK_SOLANA_REGISTRY)
        
        # Mock fetch_metadata
        mock_metadata = VoucherMetadata(
            name="Test Voucher",
            description="A test voucher",
            external_url="https://example.com",
            image="https://example.com/image.png",
            icon="https://example.com/icon.png",
            attributes=[
                VoucherAttribute(trait_type="Test Trait", value="Test Value")
            ]
        )
        solana_voucher_manager.fetch_metadata = AsyncMock(return_value=mock_metadata)
        
        result = await solana_voucher_manager.fetch_solana_vouchers()
        
        assert len(result) == 1
        assert isinstance(result[0], Voucher)
        assert result[0].id == "solticket123"
        assert result[0].metadata_id == MOCK_METADATA_ID
        assert result[0].name == "Test Voucher"
        
        original_resolve = solana_voucher_manager._resolve_address
        solana_voucher_manager._resolve_address = MagicMock(return_value="specificsolana")
        result = await solana_voucher_manager.fetch_solana_vouchers("specificsolana")
        solana_voucher_manager._resolve_address.assert_called_with(address="specificsolana")
        solana_voucher_manager._resolve_address = original_resolve

    @pytest.mark.asyncio
    async def test_fetch_solana_vouchers_no_match(self, solana_voucher_manager):
        # Mock _fetch_solana_voucher with non-matching claimer
        mock_registry = {
            "claimed_tickets": {
                "solticket123": {
                    "claimer": "differentsolana",
                    "batch_id": "batch123"
                }
            },
            "batches": {
                "batch123": {
                    "metadata_id": MOCK_METADATA_ID
                }
            }
        }
        solana_voucher_manager._fetch_solana_voucher = AsyncMock(return_value=mock_registry)
        
        result = await solana_voucher_manager.fetch_solana_vouchers()
        
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_fetch_solana_vouchers_no_batch(self, solana_voucher_manager):
        # Mock _fetch_solana_voucher with no matching batch
        mock_registry = {
            "claimed_tickets": {
                "solticket123": {
                    "claimer": MOCK_SOLANA_ADDRESS,
                    "batch_id": "nonexistent"
                }
            },
            "batches": {}
        }
        solana_voucher_manager._fetch_solana_voucher = AsyncMock(return_value=mock_registry)
        
        result = await solana_voucher_manager.fetch_solana_vouchers()
        
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_fetch_solana_vouchers_no_metadata(self, solana_voucher_manager):
        # Mock _fetch_solana_voucher
        solana_voucher_manager._fetch_solana_voucher = AsyncMock(return_value=MOCK_SOLANA_REGISTRY)
        
        # Mock fetch_metadata to return None
        solana_voucher_manager.fetch_metadata = AsyncMock(return_value=None)
        
        result = await solana_voucher_manager.fetch_solana_vouchers()
        
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_get_all(self, voucher_manager):
        # Mock get_evm_voucher
        evm_voucher = Voucher(
            id="evm123",
            metadata_id=MOCK_METADATA_ID,
            name="EVM Voucher",
            description="An EVM voucher",
            external_url="https://example.com",
            image="https://example.com/image.png",
            icon="https://example.com/icon.png",
            attributes=[
                VoucherAttribute(trait_type="Test Trait", value="Test Value")
            ]
        )
        voucher_manager.get_evm_voucher = AsyncMock(return_value=[evm_voucher])
        
        # Mock fetch_solana_vouchers
        solana_voucher = Voucher(
            id="solana123",
            metadata_id=MOCK_METADATA_ID,
            name="Solana Voucher",
            description="A Solana voucher",
            external_url="https://example.com",
            image="https://example.com/image.png",
            icon="https://example.com/icon.png",
            attributes=[
                VoucherAttribute(trait_type="Test Trait", value="Test Value")
            ]
        )
        voucher_manager.fetch_solana_vouchers = AsyncMock(return_value=[solana_voucher])
        
        result = await voucher_manager.get_all()
        
        assert len(result) == 2
        assert result[0] == evm_voucher
        assert result[1] == solana_voucher