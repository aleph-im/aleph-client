import pytest
from coincurve import PrivateKey

from aleph_client.chains.nuls1 import NulsSignature

SECRET = (
    b"\xc4\xfe\xe65\x96\x14\xb4:\r: \x05;\x12j\x9bJ"
    b"\x14\x0eY\xe3BY\x0f\xd6\xee\xfc\x9d\xfe\x8fv\xbc"
)


@pytest.mark.asyncio
async def test_sign_data():
    private_key = PrivateKey(SECRET)

    sign: NulsSignature = NulsSignature.sign_data(
        pri_key=private_key.secret, digest_bytes=b"x" * (256 // 8)
    )

    assert sign
    assert type(sign.pub_key) == bytes
    assert type(sign.digest_bytes) == bytes
    assert type(sign.sig_ser) == bytes
    assert sign.ecc_type == None


@pytest.mark.asyncio
async def test_sign_message():
    private_key = PrivateKey(SECRET)
    message = b"GOOD"

    sign: NulsSignature = await NulsSignature.sign_message(
        pri_key=private_key.secret, message=message
    )

    assert len(sign.sig_ser) == 70

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
