"""
Remote account, accessible via an API.
"""
import asyncio
from typing import Dict, Optional, Coroutine

import aiohttp.web
from aiohttp import ClientSession
from pydantic import BaseModel

from .common import BaseAccount
from ..conf import settings


class AccountProperties(BaseModel):
    chain: str
    curve: str = "secp256k1"
    address: str
    public_key: str


class RemoteAccount(BaseAccount):
    CURVE: str = "secp256k1"
    _address: str
    _public_key: str
    _session: aiohttp.ClientSession
    _host: str

    def __init__(
        self, chain: str, curve: str, address: str, public_key: str, host, session
    ):
        self.CHAIN = chain
        self.CURVE = curve
        self._address = address
        self._public_key = public_key
        self._host = host
        self._session = session

    @classmethod
    async def from_crypto_host(
        cls,
        host: Optional[str] = settings.REMOTE_CRYPTO_HOST,
        unix_socket: Optional[str] = settings.REMOTE_CRYPTO_UNIX_SOCKET,
        session: Optional[ClientSession] = None,
    ):
        if not host:
            raise TypeError("from_crypto_host() missing require argument: 'host'")

        if not session:
            connector = aiohttp.UnixConnector(path=unix_socket) if unix_socket else None
            session = aiohttp.ClientSession(connector=connector)

        async with session.get(f"{host}/properties") as response:
            response.raise_for_status()
            data = await response.json()
            properties = AccountProperties(**data)

        return cls(
            chain=properties.chain,
            curve=properties.curve,
            address=properties.address,
            public_key=properties.public_key,
            host=host,
            session=session,
        )

    def __del__(self):
        asyncio.get_event_loop().run_until_complete(self._session.close())

    @property
    def private_key(self):
        raise NotImplementedError()

    async def sign_message(self, message: Dict) -> Dict:
        """Sign a message inplace."""
        async with self._session.post(f"{self._host}/sign", json=message) as response:
            response.raise_for_status()
            return await response.json()

    def get_address(self) -> str:
        return self._address

    def get_public_key(self) -> str:
        return self._public_key
