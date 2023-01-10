import re
import abc
from typing import Union, Optional, Any, Dict, List

from aiohttp import ClientSession

from aleph_client.asynchronous import get_fallback_session
from ..conf import settings


class BaseVmCache(abc.ABC):
    """Virtual Machines can use this cache to store temporary data in memory on the host."""

    session: ClientSession

    def __init__(self, session: Optional[ClientSession] = None):
        self.session = session or get_fallback_session()

    @abc.abstractmethod
    async def get(self, key: str) -> Optional[bytes]:
        """Get the value for a given key string."""
        pass

    @abc.abstractmethod
    async def set(self, key: str, value: Union[str, bytes]) -> Any:
        """Set the value for a given key string."""
        pass

    @abc.abstractmethod
    async def delete(self, key: str) -> Any:
        """Delete the value for a given key string."""
        pass

    @abc.abstractmethod
    async def keys(self, pattern: str = "*") -> List[str]:
        """Get all keys matching a given pattern."""
        pass


class VmCache(BaseVmCache):
    """Virtual Machines can use this cache to store temporary data in memory on the host."""

    cache: Dict[str, bytes]
    api_host: str

    def __init__(self, session: Optional[ClientSession] = None, api_host: Optional[str] = None):
        super().__init__(session)
        self.cache = {}
        self.api_host = api_host if api_host else settings.API_HOST

    async def get(self, key: str) -> Optional[bytes]:
        if not re.match(r"^\w+$", key):
            raise ValueError("Key may only contain letters, numbers and underscore")
        async with self.session.get(f"{self.api_host}/cache/{key}") as resp:
            if resp.status == 404:
                return None

            resp.raise_for_status()
            return await resp.read()

    async def set(self, key: str, value: Union[str, bytes]) -> Any:
        if not re.match(r"^\w+$", key):
            raise ValueError("Key may only contain letters, numbers and underscore")
        data = value if isinstance(value, bytes) else value.encode()
        async with self.session.put(
            f"{self.api_host}/cache/{key}", data=data
        ) as resp:
            resp.raise_for_status()
            return await resp.json()

    async def delete(self, key: str) -> Any:
        if not re.match(r"^\w+$", key):
            raise ValueError("Key may only contain letters, numbers and underscore")
        async with self.session.delete(f"{self.api_host}/cache/{key}") as resp:
            resp.raise_for_status()
            return await resp.json()

    async def keys(self, pattern: str = "*") -> List[str]:
        if not re.match(r"^[\w?*^\-]+$", pattern):
            raise ValueError(
                "Pattern may only contain letters, numbers, underscore, ?, *, ^, -"
            )
        async with self.session.get(
            f"{self.api_host}/cache/?pattern={pattern}"
        ) as resp:
            resp.raise_for_status()
            return await resp.json()


class TestVmCache(BaseVmCache):
    """This is a local, dict-based cache that can be used for testing purposes."""

    def __init__(self, session: Optional[ClientSession] = None):
        super().__init__(session)
        self._cache: Dict[str, bytes] = {}

    async def get(self, key: str) -> Optional[bytes]:
        if not re.match(r"^\w+$", key):
            raise ValueError("Key may only contain letters, numbers and underscore")
        return self._cache.get(key)

    async def set(self, key: str, value: Union[str, bytes]) -> None:
        if not re.match(r"^\w+$", key):
            raise ValueError("Key may only contain letters, numbers and underscore")
        data = value if isinstance(value, bytes) else value.encode()
        self._cache[key] = data

    async def delete(self, key: str) -> None:
        if not re.match(r"^\w+$", key):
            raise ValueError("Key may only contain letters, numbers and underscore")
        del self._cache[key]

    async def keys(self, pattern: str = "*") -> List[str]:
        if not re.match(r"^[\w?*^\-]+$", pattern):
            raise ValueError(
                "Pattern may only contain letters, numbers, underscore, ?, *, ^, -"
            )
        all_keys = list(self._cache.keys())
        if pattern == "*":
            return all_keys
        return [key for key in all_keys if re.match(pattern, key)]
