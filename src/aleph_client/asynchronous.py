""" This is the simplest aleph network client available.
"""
import asyncio
import hashlib
import json
import logging
import time
from abc import abstractmethod
from datetime import datetime
from enum import Enum
from functools import lru_cache

logger = logging.getLogger(__name__)

try:
    import magic  # type:ignore
except ImportError:
    logger.warning("Could not import library 'magic'")
    magic = None  # type:ignore

from .conf import settings
from typing import Optional, Iterable, Union, Any, Dict
from typing_extensions import Protocol  # Python < 3.8

import aiohttp
from aiohttp import ClientSession

from aleph_message.models.program import ProgramContent  # type: ignore


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


@lru_cache()
def get_fallback_session() -> ClientSession:
    if settings.API_UNIX_SOCKET:
        connector = aiohttp.UnixConnector(path=settings.API_UNIX_SOCKET)
        return aiohttp.ClientSession(connector=connector)
    else:
        return aiohttp.ClientSession()


def wrap_async(func):
    def func_caller(*args, **kwargs):
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(func(*args, **kwargs))

    return func_caller


async def ipfs_push(
    content, session: Optional[ClientSession] = None, api_server: str = settings.API_HOST
) -> str:
    session = session or get_fallback_session()

    async with session.post(f"{api_server}/api/v0/ipfs/add_json", json=content) as resp:
        resp.raise_for_status()
        return (await resp.json()).get("hash")


sync_ipfs_push = wrap_async(ipfs_push)


async def storage_push(
    content, session: Optional[ClientSession] = None, api_server: str = settings.API_HOST
) -> str:
    session = session or get_fallback_session()

    async with session.post(
        f"{api_server}/api/v0/storage/add_json", json=content
    ) as resp:
        resp.raise_for_status()
        return (await resp.json()).get("hash")


sync_storage_push = wrap_async(storage_push)


async def ipfs_push_file(
    file_content,
    session: Optional[ClientSession] = None,
    api_server: str = settings.API_HOST,
) -> str:
    session = session or get_fallback_session()

    data = aiohttp.FormData()
    data.add_field("file", file_content)

    async with session.post(f"{api_server}/api/v0/ipfs/add_file", data=data) as resp:
        resp.raise_for_status()
        return (await resp.json()).get("hash")


sync_ipfs_push_file = wrap_async(ipfs_push_file)


async def storage_push_file(
    file_content,
    session: Optional[ClientSession] = None,
    api_server: str = settings.API_HOST,
) -> str:
    session = session or get_fallback_session()

    data = aiohttp.FormData()
    data.add_field("file", file_content)

    async with session.post(f"{api_server}/api/v0/storage/add_file", data=data) as resp:
        resp.raise_for_status()
        return (await resp.json()).get("hash")


sync_storage_push_file = wrap_async(storage_push_file)


async def broadcast(
    message, session: Optional[ClientSession] = None, api_server: str = settings.API_HOST
):
    session = session or get_fallback_session()

    async with session.post(
        f"{api_server}/api/v0/ipfs/pubsub/pub",
        json={"topic": "ALEPH-TEST", "data": json.dumps(message)},
    ) as response:
        response.raise_for_status()
        result = await response.json()
        if result["status"] == "warning":
            if 'failed' in result:
                # Requires recent version of Pyaleph
                logger.warning(f"Message failed to publish on {result.get('failed')}")
            else:
                logger.warning(f"Message failed to publish on IPFS and/or P2P")
        return (result).get("value")


sync_broadcast = wrap_async(broadcast)


async def create_post(
    account: Account,
    post_content,
    post_type: str,
    ref=None,
    address: Optional[str] = settings.ADDRESS_TO_USE,
    channel: str = "TEST",
    session: Optional[ClientSession] = None,
    api_server: str = settings.API_HOST,
    inline: bool = True,
    storage_engine: str = "storage",
):
    address = address or account.get_address()

    post = {
        "type": post_type,
        "address": address,
        "content": post_content,
        "time": time.time(),
    }
    if ref is not None:
        post["ref"] = ref

    return await submit(
        account,
        post,
        "POST",
        channel=channel,
        api_server=api_server,
        session=session,
        inline=inline,
        storage_engine=storage_engine,
    )


sync_create_post = wrap_async(create_post)


async def create_aggregate(
    account: Account,
    key,
    content,
    address: Optional[str] = settings.ADDRESS_TO_USE,
    channel: str = "TEST",
    session: Optional[ClientSession] = None,
    api_server: str = settings.API_HOST,
):
    address = address or account.get_address()

    post = {"key": key, "address": address, "content": content, "time": time.time()}
    return await submit(
        account,
        post,
        "AGGREGATE",
        channel=channel,
        api_server=api_server,
        session=session,
    )


sync_create_aggregate = wrap_async(create_aggregate)


async def create_store(
    account: Account,
    address=settings.ADDRESS_TO_USE,
    file_content: Optional[bytes] = None,
    file_hash: Optional[str] = None,
    guess_mime_type: bool = False,
    ref: Optional[str] = None,
    storage_engine="storage",
    extra_fields: Optional[dict] = None,
    channel: str = "TEST",
    session: Optional[ClientSession] = None,
    api_server: str = settings.API_HOST,
):
    address = address or account.get_address()
    extra_fields = extra_fields or {}

    if file_hash is None:
        if file_content is None:
            raise ValueError("Please specify at least a file_content or a file_hash")

        if storage_engine == "storage":
            file_hash = await storage_push_file(
                file_content, session=session, api_server=api_server
            )
        elif storage_engine == "ipfs":
            file_hash = await ipfs_push_file(
                file_content, session=session, api_server=api_server
            )
        else:
            raise ValueError(f"Unknown storage engine: '{storage_engine}'")

    if magic is None:
        pass
    elif guess_mime_type is True and "mime_type" not in extra_fields:
        extra_fields["mime_type"] = magic.from_buffer(file_content, mime=True)

    if ref:
        extra_fields["ref"] = ref

    store_content = {
        "address": address,
        "item_type": storage_engine,
        "item_hash": file_hash,
        "time": time.time(),
    }
    if extra_fields is not None:
        store_content.update(extra_fields)

    return await submit(
        account,
        store_content,
        "STORE",
        channel=channel,
        api_server=api_server,
        session=session,
        inline=True,
    )


sync_create_store = wrap_async(create_store)


async def create_program(
        account: Account,
        program_ref: str,
        entrypoint: str,
        runtime: str,
        data_ref: Optional[str] = None,
        storage_engine: StorageEnum = StorageEnum.storage,
        channel: str = "TEST",
        address: Optional[str] = settings.ADDRESS_TO_USE,
        session: Optional[ClientSession] = None,
        api_server: str = settings.API_HOST,
        memory: int = settings.DEFAULT_VM_MEMORY,
):
    address = address or account.get_address()

    # TODO: Check that program_ref, runtime and data_ref exist

    content = ProgramContent(**{
        "type": "vm-function",
        "address": address,
        "allow_amend": False,
        "code": {
            "encoding": "zip",
            "entrypoint": entrypoint,
            "ref": program_ref,
            "allow_amend": False,
        },
        "on": {
            "http": True,
        },
        "environment": {
            "reproducible": False,
            "internet": True,
            "aleph_api": True,
        },
        "resources": {
            "vcpus": 1,
            "memory": memory,
            "seconds": 30,
        },
        "runtime": {
            "ref": runtime,
            "allow_amend": False,
            "comment": "Aleph Alpine Linux with Python 3.8",
        },
        "data": {
            "encoding": "zip",
            "mount": "/data",
            "ref": data_ref,
            "allow_amend": False,
        } if data_ref else None,
        "time": time.time(),
    })

    return await submit(
        account=account,
        content=content.dict(),
        message_type="PROGRAM",
        channel=channel,
        api_server=api_server,
        storage_engine=StorageEnum.storage,
        session=session,
        inline=True,
    )


def sync_create_program(
        account: Account,
        program_ref: str,
        entrypoint: str,
        runtime: str,
        data_ref: Optional[str] = None,
        storage_engine: StorageEnum = StorageEnum.storage,
        channel: str = "TEST",
        address: Optional[str] = settings.ADDRESS_TO_USE,
        session: Optional[ClientSession] = None,
        api_server: str = settings.API_HOST,
        memory: int = settings.DEFAULT_VM_MEMORY,
):
    return wrap_async(create_program)(
        account=account,
        program_ref=program_ref,
        entrypoint=entrypoint,
        runtime=runtime,
        data_ref=data_ref,
        storage_engine=storage_engine,
        channel=channel,
        address=address,
        session=session,
        api_server=api_server,
        memory=memory,
    )


async def submit(
    account: Account,
    content: dict,
    message_type: str,
    channel: str = "IOT_TEST",
    api_server: str = settings.API_HOST,
    storage_engine: str = "storage",
    session: Optional[ClientSession] = None,
    inline: bool = True,
):
    message: Dict[str, Any] = {
        #'item_hash': ipfs_hash,
        "chain": account.CHAIN,
        "channel": channel,
        "sender": account.get_address(),
        "type": message_type,
        "time": time.time(),
    }

    item_content: str = json.dumps(content, separators=(",", ":"))

    if inline and (len(item_content) < 100000):
        message["item_content"] = item_content
        h = hashlib.sha256()
        h.update(message["item_content"].encode("utf-8"))
        message["item_hash"] = h.hexdigest()
    else:
        if storage_engine == "ipfs":
            message["item_hash"] = await ipfs_push(content, api_server=api_server)
        else:  # storage
            message["item_hash"] = await storage_push(content, api_server=api_server)

    message = await account.sign_message(message)
    await broadcast(message, session=session, api_server=api_server)

    # let's add the content to the object so users can access it.
    message["content"] = content
    return message


sync_submit = wrap_async(submit)


async def fetch_aggregate(
    address: str,
    key,
    session: Optional[ClientSession] = None,
    api_server: str = settings.API_HOST,
):
    session = session or get_fallback_session()

    async with session.get(
        f"{api_server}/api/v0/aggregates/{address}.json?keys={key}"
    ) as resp:
        return (await resp.json()).get("data", dict()).get(key)


sync_fetch_aggregate = wrap_async(fetch_aggregate)


async def fetch_aggregates(
    address: str,
    keys: Optional[Iterable[str]] = None,
    session: Optional[ClientSession] = None,
    api_server: str = settings.API_HOST,
) -> Dict[str, Dict]:
    session = session or get_fallback_session()

    keys_str = ",".join(keys) if keys else ""
    query_string = f"?keys={keys_str}" if keys else ""

    async with session.get(
        f"{api_server}/api/v0/aggregates/{address}.json{query_string}"
    ) as resp:
        return (await resp.json()).get("data", dict())


sync_fetch_aggregates = wrap_async(fetch_aggregates)


async def get_posts(
    pagination: int = 200,
    page: int = 1,
    types: Optional[Iterable[str]] = None,
    refs: Optional[Iterable[str]] = None,
    addresses: Optional[Iterable[str]] = None,
    tags: Optional[Iterable[str]] = None,
    hashes: Optional[Iterable[str]] = None,
    channels: Optional[Iterable[str]] = None,
    start_date: Optional[Union[datetime, float]] = None,
    end_date: Optional[Union[datetime, float]] = None,
    session: Optional[ClientSession] = None,
    api_server: str = settings.API_HOST,
):
    session = session or get_fallback_session()

    params: Dict[str, Any] = dict(pagination=pagination, page=page)

    if types is not None:
        params["types"] = ",".join(types)
    if refs is not None:
        params["refs"] = ",".join(refs)
    if addresses is not None:
        params["addresses"] = ",".join(addresses)
    if tags is not None:
        params["tags"] = ",".join(tags)
    if hashes is not None:
        params["hashes"] = ",".join(hashes)
    if channels is not None:
        params["channels"] = ",".join(channels)

    if start_date is not None:
        if not isinstance(start_date, float) and hasattr(start_date, "timestamp"):
            start_date = start_date.timestamp()
        params["start_date"] = start_date
    if end_date is not None:
        if not isinstance(end_date, float) and hasattr(start_date, "timestamp"):
            end_date = end_date.timestamp()
        params["end_date"] = end_date

    async with session.get(f"{api_server}/api/v0/posts.json", params=params) as resp:
        resp.raise_for_status()
        return await resp.json()


sync_get_posts = wrap_async(get_posts)


async def get_messages(
    pagination: int = 200,
    page: int = 1,
    message_type: Optional[str] = None,
    content_types: Optional[Iterable[str]] = None,
    refs: Optional[Iterable[str]] = None,
    addresses: Optional[Iterable[str]] = None,
    tags: Optional[Iterable[str]] = None,
    hashes: Optional[Iterable[str]] = None,
    channels: Optional[Iterable[str]] = None,
    start_date: Optional[Union[datetime, float]] = None,
    end_date: Optional[Union[datetime, float]] = None,
    session: Optional[ClientSession] = None,
    api_server: str = settings.API_HOST,
) -> Dict[str, Any]:
    session = session or get_fallback_session()

    params: Dict[str, Any] = dict(pagination=pagination, page=page)

    if message_type is not None:
        params["msgType"] = message_type
    if content_types is not None:
        params["contentTypes"] = ",".join(content_types)
    if refs is not None:
        params["refs"] = ",".join(refs)
    if addresses is not None:
        params["addresses"] = ",".join(addresses)
    if tags is not None:
        params["tags"] = ",".join(tags)
    if hashes is not None:
        params["hashes"] = ",".join(hashes)
    if channels is not None:
        params["channels"] = ",".join(channels)

    if start_date is not None:
        if not isinstance(start_date, float) and hasattr(start_date, "timestamp"):
            start_date = start_date.timestamp()
        params["start_date"] = start_date
    if end_date is not None:
        if not isinstance(end_date, float) and hasattr(start_date, "timestamp"):
            end_date = end_date.timestamp()
        params["end_date"] = end_date

    async with session.get(f"{api_server}/api/v0/messages.json", params=params) as resp:
        resp.raise_for_status()
        return await resp.json()


sync_get_messages = wrap_async(get_messages)
