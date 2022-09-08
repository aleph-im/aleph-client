from abc import abstractmethod
from enum import Enum
from typing import Protocol, Dict, TypeVar

__all__ = ("StorageEnum", "Account", "AccountFromPrivateKey")

from aleph_message.models import AlephMessage


class StorageEnum(str, Enum):
    ipfs = "ipfs"
    storage = "storage"


# Use a protocol to avoid importing crypto libraries
class Account(Protocol):
    CHAIN: str
    CURVE: str

    @abstractmethod
    async def sign_message(self, message: Dict) -> Dict:
        ...

    @abstractmethod
    def get_address(self) -> str:
        ...

    @abstractmethod
    def get_public_key(self) -> str:
        ...


class AccountFromPrivateKey(Account, Protocol):
    """Only accounts that are initialized from a private key string are supported."""

    def __init__(self, private_key: bytes):
        ...


GenericMessage = TypeVar("GenericMessage", bound=AlephMessage)
