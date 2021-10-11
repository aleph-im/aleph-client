import os
from abc import abstractmethod
from typing import Union, Dict

from coincurve import PrivateKey
from ecies import decrypt, encrypt

# In case we don't want to bother with handling private key ourselves
# do an ugly and insecure write and read from disk to this file.
PRIVATE_KEY_FILE = "device.key"


def get_verification_buffer(message):
    """Returns a serialized string to verify the message integrity
    (this is was it signed)
    """
    return "{chain}\n{sender}\n{type}\n{item_hash}".format(**message).encode("utf-8")


def get_public_key(private_key):
    privkey = PrivateKey(private_key)
    return privkey.public_key.format()


class BaseAccount:
    CHAIN: str
    CURVE: str
    private_key: Union[str, bytes]

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


def get_fallback_private_key() -> bytes:
    private_key: bytes
    try:
        with open(PRIVATE_KEY_FILE, "rb") as prvfile:
            private_key = prvfile.read()
    except OSError:
        private_key = generate_key()
        with open(PRIVATE_KEY_FILE, "wb") as prvfile:
            prvfile.write(private_key)

    return private_key


def delete_private_key_file():
    try:
        os.remove(PRIVATE_KEY_FILE)
    except FileNotFoundError:
        pass
