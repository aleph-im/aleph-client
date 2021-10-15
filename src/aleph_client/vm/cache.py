import re
from typing import Union, Optional

from aiohttp import ClientSession
from ..conf import settings
from aleph_client.asynchronous import get_fallback_session


class VmCache:
    """
    Virtual Machines can use this cache to store temporary data in memory on the host.
    """

    session: ClientSession

    def __init__(self, session: Optional[ClientSession] = None):
        self.session = session or get_fallback_session()

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
                "Patterh may only contain letters, numbers, underscore, ?, *, ^, -"
            )
        async with self.session.get(
            f"{settings.API_HOST}/cache/?pattern={pattern}"
        ) as resp:
            resp.raise_for_status()
            return await resp.json()
