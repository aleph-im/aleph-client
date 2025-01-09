from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock

from aleph.sdk.chains.evm import EVMAccount
from aleph.sdk.conf import settings
from eth_utils.currency import to_wei
from pydantic import BaseModel

# Change to Aleph testnet
settings.API_HOST = "https://api.twentysix.testnet.network"

# Utils
FAKE_PRIVATE_KEY = b"cafe" * 8
FAKE_PUBKEY_FILE = "/path/fake/pubkey"
FAKE_ADDRESS_EVM = "0x00001A0e6B9a46Be48a294D74D897d9C48678862"
FAKE_STORE_HASH = "102682ea8bcc0cec9c42f32fbd2660286b4eb31003108440988343726304607a"  # Has to exist on Aleph Testnet
FAKE_STORE_HASH_CONTENT_FILE_CID = "QmX8K1c22WmQBAww5ShWQqwMiFif7XFrJD6iFBj7skQZXW"  # From FAKE_STORE_HASH message
FAKE_VM_HASH = "ab12" * 16
FAKE_PROGRAM_HASH = "cd34" * 16
FAKE_PROGRAM_HASH_2 = "ef56" * 16
FAKE_CRN_HASH = "cd34" * 16
FAKE_CRN_URL = "https://ovh.staging.aleph.sh"
FAKE_FLOW_HASH = "0xfake_flow_hash"


class Dict(BaseModel):
    class Config:
        extra = "allow"


def create_test_account() -> EVMAccount:
    return EVMAccount(private_key=FAKE_PRIVATE_KEY)


def create_mock_load_account():
    mock_account = create_test_account()
    mock_loader = MagicMock(return_value=mock_account)
    mock_loader.return_value.get_super_token_balance = MagicMock(return_value=Decimal(10000 * (10**18)))
    mock_loader.return_value.can_transact = MagicMock(return_value=True)
    mock_loader.return_value.superfluid_connector = MagicMock(can_start_flow=MagicMock(return_value=True))
    mock_loader.return_value.get_flow = AsyncMock(return_value={"flowRate": to_wei(0.0001, unit="ether")})
    mock_loader.return_value.create_flow = AsyncMock(return_value=FAKE_FLOW_HASH)
    mock_loader.return_value.update_flow = AsyncMock(return_value=FAKE_FLOW_HASH)
    mock_loader.return_value.delete_flow = AsyncMock(return_value=FAKE_FLOW_HASH)
    return mock_loader
