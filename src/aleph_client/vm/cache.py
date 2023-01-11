import abc
import fnmatch
import re
from typing import Union, Optional, Any, Dict, List, NewType

import aiohttp

CacheKey = NewType("CacheKey", str)


def sanitize_cache_key(key: str) -> CacheKey:
    if not re.match(r"^\w+$", key):
        raise ValueError("Key may only contain letters, numbers and underscore")
    return CacheKey(key)


class BaseVmCache(abc.ABC):
    """Virtual Machines can use this cache to store temporary data in memory on the host."""

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
        """Get all keys matching a given glob pattern."""
        pass


class VmCache(BaseVmCache):
    """Virtual Machines can use this cache to store temporary data in memory on the host."""

    session: aiohttp.ClientSession
    cache: Dict[str, bytes]

    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
        self.cache = {}

    async def get(self, key: str) -> Optional[bytes]:
        sanitized_key = sanitize_cache_key(key)
        async with self.session.get(f"/cache/{sanitized_key}") as resp:
            if resp.status == 404:
                return None

            resp.raise_for_status()
            return await resp.read()

    async def set(self, key: str, value: Union[str, bytes]) -> Any:
        sanitized_key = sanitize_cache_key(key)
        data = value if isinstance(value, bytes) else value.encode()
        async with self.session.put(f"/cache/{sanitized_key}", data=data) as resp:
            resp.raise_for_status()
            return await resp.json()

    async def delete(self, key: str) -> Any:
        sanitized_key = sanitize_cache_key(key)
        async with self.session.delete(f"/cache/{sanitized_key}") as resp:
            resp.raise_for_status()
            return await resp.json()

    async def keys(self, pattern: str = "*") -> List[str]:
        if not re.match(r"^[\w?*^\-]+$", pattern):
            raise ValueError(
                "Pattern may only contain letters, numbers, underscore, ?, *, ^, -"
            )
        async with self.session.get(f"/cache/?pattern={pattern}") as resp:
            resp.raise_for_status()
            return await resp.json()


class TestVmCache(BaseVmCache):
    """This is a local, dict-based cache that can be used for testing purposes."""

    def __init__(self):
        self._cache: Dict[str, bytes] = {}

    async def get(self, key: str) -> Optional[bytes]:
        sanitized_key = sanitize_cache_key(key)
        return self._cache.get(sanitized_key)

    async def set(self, key: str, value: Union[str, bytes]) -> None:
        sanitized_key = sanitize_cache_key(key)
        data = value if isinstance(value, bytes) else value.encode()
        self._cache[sanitized_key] = data

    async def delete(self, key: str) -> None:
        sanitized_key = sanitize_cache_key(key)
        del self._cache[sanitized_key]

    async def keys(self, pattern: str = "*") -> List[str]:
        if not re.match(r"^[\w?*^\-]+$", pattern):
            raise ValueError(
                "Pattern may only contain letters, numbers, underscore, ?, *, ^, -"
            )
        all_keys = list(self._cache.keys())
        return fnmatch.filter(all_keys, pattern)
