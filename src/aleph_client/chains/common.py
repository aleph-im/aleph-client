import os
from abc import abstractmethod, ABC
from pathlib import Path
from typing import Dict, Optional

from coincurve.keys import PrivateKey
from ecies import decrypt, encrypt

from aleph_client.conf import settings


def get_verification_buffer(message):
    """Returns a serialized string to verify the message integrity
    (this is was it signed)
    """
    return "{chain}\n{sender}\n{type}\n{item_hash}".format(**message).encode("utf-8")


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
