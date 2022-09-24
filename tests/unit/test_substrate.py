from dataclasses import dataclass, asdict
import pytest
from aleph_client.chains.substrate import DOTAccount, get_fallback_account, get_fallback_mnemonics
from aleph_client.chains.common import delete_private_key_file, get_verification_buffer
from substrateinterface import Keypair

@dataclass
class Message:
    chain: str
    sender: str
    type: str
    item_hash: str
    
    
def test_get_fallback_account():
    delete_private_key_file()
    mnemonic = get_fallback_mnemonics()
    assert Keypair.validate_mnemonic(mnemonic)
    keypair = Keypair.create_from_mnemonic(mnemonic)
    account : DOTAccount(mnemonics = mnemonic) = get_fallback_account()
    assert account.CHAIN == "DOT"
    assert account.CURVE == "sr25519"
    assert keypair.mnemonic == mnemonic
    assert keypair.ss58_address == account.get_address()
    
@pytest.mark.asyncio
async def test_sign_message():
    message = b"ALEPH" 
    mnemonic = get_fallback_mnemonics()
    keypair = Keypair.create_from_mnemonic(mnemonic)
    account: DOTAccount = get_fallback_account()
    
    assert keypair.ss58_address == account.get_address()
    message = asdict(Message("DOT", account.get_address(), "SomeType", "ItemHash"))
    verif = get_verification_buffer(message).decode("utf-8")
    sig = {"curve": account.CURVE, "data": keypair.sign(verif)}
    
    await account.sign_message(message)
    address = message["sender"]
    assert address
    assert type(address) == str
    assert type(message["signature"]) == str