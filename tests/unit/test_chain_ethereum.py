from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest
from dataclasses import dataclass, asdict

from aleph_client.chains.ethereum import ETHAccount, get_fallback_account


@dataclass
class Message:
    chain: str
    sender: str
    type: str
    item_hash: str


def test_get_fallback_account():
    with NamedTemporaryFile() as private_key_file:
        account = get_fallback_account(path=Path(private_key_file.name))
        assert account.CHAIN == "ETH"
        assert account.CURVE == "secp256k1"
        assert account._account.address


@pytest.mark.asyncio
async def test_ETHAccount(ethereum_account):
    account = ethereum_account

    message = Message("ETH", account.get_address(), "SomeType", "ItemHash")
    signed = await account.sign_message(asdict(message))
    assert signed["signature"]
    assert len(signed["signature"]) == 132

    address = account.get_address()
    assert address
    assert type(address) == str
    assert len(address) == 42

    pubkey = account.get_public_key()
    assert type(pubkey) == str
    assert len(pubkey) == 68


@pytest.mark.asyncio
async def test_decrypt_secp256k1(ethereum_account):
    account = ethereum_account

    assert account.CURVE == "secp256k1"
    content = b"SomeContent"

    encrypted = await account.encrypt(content)
    assert type(encrypted) == bytes
    decrypted = await account.decrypt(encrypted)
    assert type(decrypted) == bytes
    assert content == decrypted
