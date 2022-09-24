import json
from typing import Dict

from aleph_pytezos.crypto.key import Key
from nacl.public import SealedBox
from nacl.signing import SigningKey

from .common import (
    BaseAccount,
    get_fallback_private_key,
    get_verification_buffer,
)


class TezosAccount(BaseAccount):
    CHAIN = "TEZOS"
    CURVE = "secp256k1"
    _account: Key

    def __init__(self, private_key: bytes):
        self.private_key = private_key
        self._account = Key.from_secret_exponent(self.private_key)
        self._signing_key = SigningKey(self.private_key)
        self._private_key = self._signing_key.to_curve25519_private_key()

    async def sign_message(self, message: Dict) -> Dict:
        """Sign a message inplace."""
        message = self._setup_sender(message)

        verif = get_verification_buffer(message)
        sig = {
            "publicKey": self.get_public_key(),
            "signature": self._account.sign(verif),
        }

        message["signature"] = json.dumps(sig)
        return message

    def get_address(self) -> str:
        return self._account.public_key_hash()

    def get_public_key(self) -> str:
        return self._account.public_key()

    async def encrypt(self, content) -> bytes:
        return SealedBox(self._private_key.public_key).encrypt(content)

    async def decrypt(self, content) -> bytes:
        return SealedBox(self._private_key).decrypt(content)


def get_fallback_account() -> TezosAccount:
    return TezosAccount(private_key=get_fallback_private_key())
