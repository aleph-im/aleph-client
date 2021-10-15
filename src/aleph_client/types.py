from abc import abstractmethod
from enum import Enum
from typing import Protocol, Union, Dict

__all__ = ("StorageEnum", "Account")


class StorageEnum(str, Enum):
    ipfs = "ipfs"
    storage = "storage"


# Use a protocol to avoid importing crypto libraries
class Account(Protocol):
    CHAIN: str
    CURVE: str
    private_key: Union[str, bytes]

    @abstractmethod
    async def sign_message(self, message: Dict) -> Dict:
        ...

    @abstractmethod
    def get_address(self) -> str:
        ...

    @abstractmethod
    def get_public_key(self) -> str:
        ...

    @abstractmethod
    async def decrypt(self, content) -> bytes:
        ...
