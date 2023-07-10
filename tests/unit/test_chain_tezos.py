from dataclasses import asdict, dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest
from aleph.sdk.chains.tezos import TezosAccount, get_fallback_account


@dataclass
class Message:
    chain: str
    sender: str
    type: str
    item_hash: str


def test_get_fallback_account(tezos_account: TezosAccount):
    with NamedTemporaryFile() as private_key_file:
        account: TezosAccount = get_fallback_account(path=Path(private_key_file.name))

        assert account.CHAIN == "TEZOS"
        assert account.CURVE == "secp256k1"
        assert account._account.public_key()


@pytest.mark.asyncio
async def test_tezos_account(tezos_account: TezosAccount):

    message = Message("TEZOS", tezos_account.get_address(), "SomeType", "ItemHash")
    signed = await tezos_account.sign_message(asdict(message))
    assert signed["signature"]
    assert len(signed["signature"]) == 188

    address = tezos_account.get_address()
    assert address is not None
    assert isinstance(address, str)
    assert len(address) == 36

    pubkey = tezos_account.get_public_key()
    assert isinstance(pubkey, str)
    assert len(pubkey) == 55


@pytest.mark.asyncio
async def test_decrypt_secp256k1(tezos_account: TezosAccount):
    assert tezos_account.CURVE == "secp256k1"
    content = b"SomeContent"

    encrypted = await tezos_account.encrypt(content)
    assert isinstance(encrypted, bytes)
    decrypted = await tezos_account.decrypt(encrypted)
    assert isinstance(decrypted, bytes)
    assert content == decrypted
