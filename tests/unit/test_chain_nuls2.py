import pytest
import json
from coincurve import PrivateKey
import base64, base58

from dataclasses import dataclass, asdict
from aleph_client.chains.nuls1 import address_from_hash
from aleph_client.chains.nuls2 import get_fallback_account, NULSAccount
from aleph_client.chains.common import delete_private_key_file


SECRET = (
    b"\xc4\xfe\xe65\x96\x14\xb4:\r: \x05;\x12j\x9bJ"
    b"\x14\x0eY\xe3BY\x0f\xd6\xee\xfc\x9d\xfe\x8fv\xbc"
)

@dataclass
class Message:
    chain: str
    sender: str
    item_hash: str
    type: str
    

def test_get_fallback_account():
    delete_private_key_file()
    account: NULSAccount = get_fallback_account(chain_id=1)

    assert account.CHAIN == "NULS2"
    assert account.CURVE == "secp256k1"
    assert account.chain_id == 1
    assert type(account.private_key) == bytes
    assert len(account.private_key) == 32
    

@pytest.mark.asyncio
async def test_sign_message():
    delete_private_key_file()
    account: NULSAccount = get_fallback_account(chain_id=1)
    
    # private_key = PrivateKey(SECRET)
    
    message = asdict(Message("NULS2", account.get_address(), "SomeType", "ItemHash"))
    # sign = await account.sign_message(message)
    address = message["sender"]
    assert type(address) == str
    chain = message["chain"]
    assert type(chain) == str
    pubKey = base58.b58decode(address)
    assert type(pubKey) == bytes
    assert len(pubKey) == 27