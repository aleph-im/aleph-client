import json
from typing import Dict

from nacl.signing import SigningKey
from nacl.public import PublicKey, PrivateKey, SealedBox
import base58

from .common import (
    BaseAccount,
    get_verification_buffer,
    get_public_key,
    PRIVATE_KEY_FILE,
)


def encode(item):
    return base58.b58encode(bytes(item)).decode("ascii")


class SOLAccount(BaseAccount):
    CHAIN = "SOL"
    CURVE = "curve25519"
    _signing_key: SigningKey
    _private_key: PrivateKey

    def __init__(self, private_key=None):
        self.private_key = private_key
        self._signing_key = SigningKey(self.private_key)
        self._private_key = self._signing_key.to_curve25519_private_key()

    async def sign_message(self, message: Dict) -> Dict:
        """Sign a message inplace."""
        message = self._setup_sender(message)
        verif = get_verification_buffer(message)
        sig = {
            "publicKey": self.get_address(),
            "signature": encode(self._signing_key.sign(verif).signature),
        }
        message["signature"] = json.dumps(sig)
        return message

    def get_address(self) -> str:
        return encode(self._signing_key.verify_key)

    def get_public_key(self) -> str:
        return bytes(self._signing_key.verify_key.to_curve25519_public_key()).hex()

    async def encrypt(self, content) -> bytes:
        value: bytes = bytes(SealedBox(self._private_key.public_key).encrypt(content))
        return value

    async def decrypt(self, content) -> bytes:
        value: bytes = SealedBox(self._private_key).decrypt(content)
        return value


def get_fallback_account() -> SOLAccount:
    return SOLAccount(private_key=get_fallback_private_key())


def get_fallback_private_key():
    try:
        with open(PRIVATE_KEY_FILE, "rb") as prvfile:
            pkey = prvfile.read()
    except OSError:
        pkey = bytes(SigningKey.generate())
        with open(PRIVATE_KEY_FILE, "wb") as prvfile:
            prvfile.write(pkey)

    return pkey
