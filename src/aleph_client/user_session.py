import asyncio

import aiohttp

from aleph_client.types import Account


class UserSession:
    account: Account
    api_server: str
    http_session: aiohttp.ClientSession

    def __init__(self,  account: Account, api_server: str):
        self.account = account
        self.api_server = api_server
        self.http_session = aiohttp.ClientSession(base_url=api_server)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        asyncio.run(self.http_session.close())

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.http_session.close()
