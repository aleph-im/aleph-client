import pytest
from coincurve import PrivateKey

from aleph_client.chains.nuls1 import NulsSignature, VarInt, write_with_length
from dataclasses import dataclass
from aleph_client.chains.nuls1 import get_fallback_account, NULSAccount
from aleph_client.chains.common import delete_private_key_file


SECRET = (
    b"\xc4\xfe\xe65\x96\x14\xb4:\r: \x05;\x12j\x9bJ"
    b"\x14\x0eY\xe3BY\x0f\xd6\xee\xfc\x9d\xfe\x8fv\xbc"
)

@dataclass
class Message:
    chain: str
    sender: str
    type: str
    item_hash: str

async def test_get_fallback_account():
    delete_private_key_file()
    account: NULSAccount = get_fallback_account(chain_id=8964)

    assert account.CHAIN == "NULS"
    assert account.CURVE == "secp256k1"
    assert type(account.private_key) == bytes
    # assert len(account.private_key) == 10


@pytest.mark.asyncio
async def test_sign_data():
    private_key = PrivateKey(SECRET)

    sign: NulsSignature = NulsSignature.sign_data(
        pri_key=private_key.secret, digest_bytes=b"x" * (256 // 8)
    )
        
    assert sign
    assert type(sign.pub_key) == bytes
    assert len(sign.pub_key) == 33
    assert type(sign.digest_bytes) == bytes
    assert len(private_key.secret) == 32
    assert type(sign.sig_ser) == bytes
    assert sign.ecc_type == None


@pytest.mark.asyncio
async def test_sign_message():
    private_key = PrivateKey(SECRET)
    message = b"ALEPH" 

    sign: NulsSignature = await NulsSignature.sign_message(
        pri_key=private_key.secret, message=message
    )

    assert len(sign.sig_ser) == 70
    assert len(message) == 5
    assert type(message) == bytes
    assert VarInt(len(message)).encode() == b'\x05'
    assert sign
    assert type(sign.pub_key) == bytes
    assert sign.digest_bytes == None
    assert type(sign.sig_ser) == bytes
    assert sign.ecc_type == None


@pytest.mark.asyncio
async def test_verify():
    private_key = PrivateKey(SECRET)
    message = b"GOOD"

    sign: NulsSignature = await NulsSignature.sign_message(
        pri_key=private_key.secret, message=message
    )

    assert sign.verify(message=message)
    assert not sign.verify(message=b"BAD")

@pytest.mark.asyncio
async def test_serialize():
    
    private_key = PrivateKey(SECRET)
    message = b"ALEPH" 

    sign: NulsSignature = await NulsSignature.sign_message(
        pri_key=private_key.secret, message=message
    )
    
    serie = NulsSignature(sign.pub_key)
    assert serie.serialize()