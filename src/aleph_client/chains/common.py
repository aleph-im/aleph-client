import os
from abc import abstractmethod, ABC
from pathlib import Path
from typing import Dict, Optional, Any, Mapping

from coincurve.keys import PrivateKey
from ecies import decrypt, encrypt
from aleph_message.models import Chain, MessageType

from aleph_client.conf import settings


def get_verification_buffer(message: Mapping[str, Any]) -> bytes:
    """
    Returns a buffer to sign to authenticate the message on the aleph.im network.
    """

    # Support both strings and enums. Python 3.11 changed the formatting of enums,
    # so we must use `.value`.
    chain = message["chain"]
    chain_str = chain.value if isinstance(chain, Chain) else chain

    message_type = message["type"]
    message_type_str = (
        message_type.value if isinstance(message_type, MessageType) else message_type
    )

    buffer = (
        f"{chain_str}\n{message['sender']}\n{message_type_str}\n{message['item_hash']}"
    )
    return buffer.encode("utf-8")


def get_public_key(private_key):
    privkey = PrivateKey(private_key)
    return privkey.public_key.format()


class BaseAccount(ABC):
    CHAIN: str
    CURVE: str
    private_key: bytes

    def _setup_sender(self, message: Dict) -> Dict:
        """Set the sender of the message as the account's public key.
        If a sender is already specified, check that it matches the account's public key.
        """
        if not message.get("sender"):
            message["sender"] = self.get_address()
            return message
        elif message["sender"] == self.get_address():
            return message
        else:
            raise ValueError("Message sender does not match the account's public key.")

    @abstractmethod
    async def sign_message(self, message: Dict) -> Dict:
        raise NotImplementedError

    @abstractmethod
    def get_address(self) -> str:
        raise NotImplementedError

    @abstractmethod
    def get_public_key(self) -> str:
        raise NotImplementedError

    async def encrypt(self, content) -> bytes:
        if self.CURVE == "secp256k1":
            value: bytes = encrypt(self.get_public_key(), content)
            return value
        else:
            raise NotImplementedError

    async def decrypt(self, content) -> bytes:
        if self.CURVE == "secp256k1":
            value: bytes = decrypt(self.private_key, content)
            return value
        else:
            raise NotImplementedError


# Start of the ugly stuff
def generate_key() -> bytes:
    privkey = PrivateKey()
    return privkey.secret


def get_fallback_private_key(path: Optional[Path] = None) -> bytes:
    path = path or settings.PRIVATE_KEY_FILE
    private_key: bytes
    if path.exists() and path.stat().st_size > 0:
        with open(path, "rb") as prvfile:
            private_key = prvfile.read()
    else:
        private_key = generate_key()
        os.makedirs(path.parent, exist_ok=True)
        with open(path, "wb") as prvfile:
            prvfile.write(private_key)

        with open(path, "rb") as prvfile:
            print(prvfile.read())

        default_key_path = path.parent / "default.key"
        if not default_key_path.is_symlink():
            # Create a symlink to use this key by default
            os.symlink(path, default_key_path)
    return private_key
