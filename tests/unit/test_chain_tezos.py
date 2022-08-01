import pytest

from aleph_client.chains.common import delete_private_key_file
from aleph_client.chains.tezos import TezosAccount, get_fallback_account
from dataclasses import dataclass, asdict


@dataclass
class Message:
    chain: str
    sender: str
    type: str
    item_hash: str


def test_get_fallback_account():
    delete_private_key_file()
    account: TezosAccount = get_fallback_account()

    assert account.CHAIN == "TEZOS"
    assert account.CURVE == "secp256k1"
    assert account._account.public_key()


@pytest.mark.asyncio
async def test_tezos_account():
    account: TezosAccount = get_fallback_account()

    message = Message("TEZOS", account.get_address(), "SomeType", "ItemHash")
    signed = await account.sign_message(asdict(message))
    assert signed["signature"]
    assert len(signed["signature"]) == 188

    address = account.get_address()
    assert address is not None
    assert isinstance(address, str)
    assert len(address) == 36

    pubkey = account.get_public_key()
    assert isinstance(pubkey, str)
    assert len(pubkey) == 55


@pytest.mark.asyncio
async def test_decrypt_secp256k1():
    account: TezosAccount = get_fallback_account()

    assert account.CURVE == "secp256k1"
    content = b"SomeContent"

    encrypted = await account.encrypt(content)
    assert isinstance(encrypted, bytes)
    decrypted = await account.decrypt(encrypted)
    assert isinstance(decrypted, bytes)
    assert content == decrypted
