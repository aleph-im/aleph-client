import re
import abc
from typing import Union, Optional

from aiohttp import ClientSession

from aleph_client.asynchronous import get_fallback_session
from ..conf import settings


class BaseVmCache(abc.ABC):
    """Virtual Machines can use this cache to store temporary data in memory on the host."""

    session: ClientSession

    def __init__(self, session: Optional[ClientSession] = None):
        self.session = session or get_fallback_session()

    @abc.abstractmethod
    async def get(self, key: str):
        pass

    @abc.abstractmethod
    async def set(self, key: str, value: Union[str, bytes]):
        pass

    @abc.abstractmethod
    async def delete(self, key: str):
        pass

    @abc.abstractmethod
    async def keys(self, pattern: str = "*"):
        pass


class VmCache(BaseVmCache):
    """Virtual Machines can use this cache to store temporary data in memory on the host."""

    async def get(self, key: str):
        if not re.match(r"^\w+$", key):
            raise ValueError("Key may only contain letters, numbers and underscore")
        async with self.session.get(f"{settings.API_HOST}/cache/{key}") as resp:
            if resp.status == 404:
                return None

            resp.raise_for_status()
            return await resp.read()

    async def set(self, key: str, value: Union[str, bytes]):
        if not re.match(r"^\w+$", key):
            raise ValueError("Key may only contain letters, numbers and underscore")
        data = value if isinstance(value, bytes) else value.encode()
        async with self.session.put(
            f"{settings.API_HOST}/cache/{key}", data=data
        ) as resp:
            resp.raise_for_status()
            return await resp.json()

    async def delete(self, key: str):
        if not re.match(r"^\w+$", key):
            raise ValueError("Key may only contain letters, numbers and underscore")
        async with self.session.delete(f"{settings.API_HOST}/cache/{key}") as resp:
            resp.raise_for_status()
            return await resp.json()

    async def keys(self, pattern: str = "*"):
        if not re.match(r"^[\w?*^\-]+$", pattern):
            raise ValueError(
                "Pattern may only contain letters, numbers, underscore, ?, *, ^, -"
            )
        async with self.session.get(
            f"{settings.API_HOST}/cache/?pattern={pattern}"
        ) as resp:
            resp.raise_for_status()
            return await resp.json()


class LocalVmCache:
    """This is a local cache that can be used for testing purposes."""

    def __init__(self):
        self._cache = {}

    async def get(self, key: str):
        return self._cache.get(key)

    async def set(self, key: str, value: Union[str, bytes]):
        self._cache[key] = value

    async def delete(self, key: str):
        del self._cache[key]

    async def keys(self, pattern: str = "*"):
        if not re.match(r"^[\w?*^\-]+$", pattern):
            raise ValueError(
                "Pattern may only contain letters, numbers, underscore, ?, *, ^, -"
            )
        all_keys = list(self._cache.keys())
        if pattern == "*":
            return all_keys
        return [key for key in all_keys if re.match(pattern, key)]