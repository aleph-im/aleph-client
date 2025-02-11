from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock

from aleph.sdk.chains.evm import EVMAccount
from aleph.sdk.conf import settings
from eth_utils.currency import to_wei
from pydantic import BaseModel

from aleph_client.commands.node import NodeInfo

# Change to Aleph testnet
# settings.API_HOST = "https://api.twentysix.testnet.network"
settings.API_HOST = "http://51.159.223.120:4024"  # TODO: Revert before release

# Utils
FAKE_PRIVATE_KEY = b"cafe" * 8
FAKE_PUBKEY_FILE = "/path/fake/pubkey"
FAKE_ADDRESS_EVM = "0x00001A0e6B9a46Be48a294D74D897d9C48678862"
# FAKE_STORE_HASH = "102682ea8bcc0cec9c42f32fbd2660286b4eb31003108440988343726304607a"  # Has to exist on Aleph Testnet
# FAKE_STORE_HASH_CONTENT_FILE_CID = "QmX8K1c22WmQBAww5ShWQqwMiFif7XFrJD6iFBj7skQZXW"  # From FAKE_STORE_HASH message
# FAKE_STORE_HASH_PUBLISHER = "0x74F82AC22C1EB20dDb9799284FD8D60eaf48A8fb"  # From FAKE_STORE_HASH message
FAKE_STORE_HASH = "5b868dc8c2df0dd9bb810b7a31cc50c8ad1e6569905e45ab4fd2eee36fecc4d2"  # TODO: Revert before release
FAKE_STORE_HASH_CONTENT_FILE_CID = "QmXSEnpQCnUfeGFoSjY1XAK1Cuad5CtAaqyachGTtsFSuA"  # TODO: Revert before release
FAKE_STORE_HASH_PUBLISHER = "0xe0aaF578B287de16852dbc54Ae34a263FF2F4b9E"  # TODO: Revert before release
FAKE_VM_HASH = "ab12" * 16
FAKE_PROGRAM_HASH = "cd34" * 16
FAKE_PROGRAM_HASH_2 = "ef56" * 16
FAKE_CRN_HASH = "cb764fe80f76cd5ec395952263fcbf0f5d2cc0dfe1ed98c90e13734b3fb2df3e"
FAKE_CRN_URL = "https://coco-1.crn.aleph.sh"
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


async def mock_fetch_nodes() -> NodeInfo:
    node_aggregate = {
        "address": "0xa1B3bb7d2332383D96b7796B908fB7f7F3c2Be10",
        "data": {
            "corechannel": {
                "nodes": [
                    {
                        "hash": "37bcf3b0de2b95168557dccd757e3fb9310f6182eb35173dd929e535dc8d18cc",
                        "name": "Aleph.Cloud.One",
                        "time": 1608436347.148,
                        "owner": "0x13CA00cD3BB1ded822AFF447a6fEC5ed9DaeCD65",
                        "score": 0.95672722675568,
                        "banner": "",
                        "locked": False,
                        "reward": "0x462b25B706688a7174d675e4787d2DBEE72aB71f",
                        "status": "active",
                        "address": "",
                        "manager": "",
                        "picture": "81410c35ea8d31569011c091d7c780e83b8e8d44bf292e6f8bf6316b162dda9e",
                        "stakers": {
                            "0x160f9C91858940BEBA3bacAD2Fc1c4D32635913b": 21359.3722761429,
                            "0x161F0F8d70971EB7fE65Fa3558e48442c338EBde": 16778.2001223581,
                            "0x2BACCdD22C27F84DE8a8EeC0aB7B2a4766E7C02d": 24072.424430756,
                        },
                        "has_bonus": True,
                        "authorized": [],
                        "description": (
                            "Supporting Aleph from NULS POCM through to running a node. Moshe is a "
                            "genius!\n\nPowered by Node Forge."
                        ),
                        "performance": 0.915326986415614,
                        "multiaddress": "/ip4/51.79.82.13/tcp/4025/p2p/QmfKB9q89aCX3wqkiqgis9SHfx2MznGd6LTsqektdKUBg5",
                        "total_staked": 1032817.18542335,
                        "score_updated": True,
                        "stream_reward": "",
                        "inactive_since": None,
                        "resource_nodes": [
                            "d1401d7f2e4487b1b956acf8de6a48de5bc5ed9637516f901dfe4eb9f74ac214",
                            "3b06f6fb75902821eeeddf713837f6a2d38aedff8a7c66c7fa3192b461df6e6a",
                            "3fe5eecb0dc99be68e197d1ccf037aa4274d30b0f94f955cf765545bebad33c3",
                            "179317d603edf7c005286dcb79968be294218fdd73ccee3bef719006a0db664c",
                            "936d1ac993deef3b09c06674e05aa742f4270ec337b1d60ec8021fccaf8f6479",
                        ],
                        "decentralization": 0.534862998440633,
                        "registration_url": "",
                        "terms_and_conditions": "",
                    },
                ],
                "resource_nodes": [
                    {
                        "hash": "cb764fe80f76cd5ec395952263fcbf0f5d2cc0dfe1ed98c90e13734b3fb2df3e",
                        "name": "Aleph.im Confidential Host 1",
                        "time": 1723565390.963,
                        "type": "compute",
                        "owner": "0xFeF2b33478f906eDE5ee96110b2342861cF1569A",
                        "score": 0.931334273816828,
                        "banner": "",
                        "locked": False,
                        "parent": "c5a1295c20d5fb1df638e4ff7dee2239ab88c2843899bd26e4b0200a9f5ca82b",
                        "reward": "0xFeF2b33478f906eDE5ee96110b2342861cF1569A",
                        "status": "linked",
                        "address": "https://coco-1.crn.aleph.sh/",
                        "manager": "",
                        "picture": "",
                        "authorized": "",
                        "description": "",
                        "performance": 0.867383529585918,
                        "multiaddress": "",
                        "score_updated": True,
                        "stream_reward": "0xFeF2b33478f906eDE5ee96110b2342861cF1569A",
                        "inactive_since": None,
                        "decentralization": 0.991886443254677,
                        "registration_url": "",
                        "terms_and_conditions": "",
                    }
                ],
            }
        },
        "info": {},
    }
    return NodeInfo(**node_aggregate)
