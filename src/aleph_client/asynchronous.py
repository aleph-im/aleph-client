""" This is the simplest aleph network client available.
"""
import asyncio
import hashlib
import json
import logging
import queue
import threading
import time
from datetime import datetime
from functools import lru_cache

from yarl import URL

from aleph_client.types import Account, StorageEnum

logger = logging.getLogger(__name__)

try:
    import magic  # type:ignore
except ImportError:
    logger.info("Could not import library 'magic', MIME type detection disabled")
    magic = None  # type:ignore

from .conf import settings
from typing import Optional, Iterable, Union, Any, Dict, List, AsyncIterable

import aiohttp
from aiohttp import ClientSession

from aleph_message.models.program import ProgramContent, Encoding  # type: ignore


@lru_cache()
def _get_fallback_session(thread_id: Optional[int]) -> ClientSession:
    if settings.API_UNIX_SOCKET:
        connector = aiohttp.UnixConnector(path=settings.API_UNIX_SOCKET)
        return aiohttp.ClientSession(connector=connector)
    else:
        return aiohttp.ClientSession()


def get_fallback_session() -> ClientSession:
    thread_id = threading.get_native_id()
    return _get_fallback_session(thread_id=thread_id)


async def ipfs_push(
    content,
    session: Optional[ClientSession] = None,
    api_server: str = settings.API_HOST,
) -> str:
    session = session or get_fallback_session()

    async with session.post(f"{api_server}/api/v0/ipfs/add_json", json=content) as resp:
        resp.raise_for_status()
        return (await resp.json()).get("hash")


async def storage_push(
    content,
    session: Optional[ClientSession] = None,
    api_server: str = settings.API_HOST,
) -> str:
    session = session or get_fallback_session()

    async with session.post(
        f"{api_server}/api/v0/storage/add_json", json=content
    ) as resp:
        resp.raise_for_status()
        return (await resp.json()).get("hash")


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


async def broadcast(
    message,
    session: Optional[ClientSession] = None,
    api_server: str = settings.API_HOST,
):
    session = session or get_fallback_session()

    async with session.post(
        f"{api_server}/api/v0/ipfs/pubsub/pub",
        json={"topic": "ALEPH-TEST", "data": json.dumps(message)},
    ) as response:
        response.raise_for_status()
        result = await response.json()
        if result["status"] == "warning":
            if result.get("failed"):
                # Requires recent version of Pyaleph
                if result["failed"] == ["p2p"]:
                    logger.info(
                        f"Message published on IPFS but failed to publish on P2P"
                    )
                else:
                    logger.warning(
                        f"Message published but failed on {result.get('failed')}"
                    )
            else:
                logger.warning(f"Message failed to publish on IPFS and/or P2P")
        return result.get("value")


async def create_post(
    account: Account,
    post_content,
    post_type: str,
    ref: Optional[str] = None,
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


async def create_program(
    account: Account,
    program_ref: str,
    entrypoint: str,
    runtime: str,
    storage_engine: StorageEnum = StorageEnum.storage,
    channel: str = "TEST",
    address: Optional[str] = settings.ADDRESS_TO_USE,
    session: Optional[ClientSession] = None,
    api_server: str = settings.API_HOST,
    memory: int = settings.DEFAULT_VM_MEMORY,
    encoding: Encoding = Encoding.zip,
    volumes: List[Dict] = None,
    subscriptions: Optional[List[Dict]] = None,
):
    volumes = volumes if volumes is not None else []

    address = address or account.get_address()

    # TODO: Check that program_ref, runtime and data_ref exist

    ## Register the different ways to trigger a VM
    if subscriptions:
        # Trigger on HTTP calls and on Aleph message subscriptions.
        triggers = {"http": True, "message": subscriptions}
    else:
        # Trigger on HTTP calls.
        triggers = {"http": True}

    content = ProgramContent(
        **{
            "type": "vm-function",
            "address": address,
            "allow_amend": False,
            "code": {
                "encoding": encoding,
                "entrypoint": entrypoint,
                "ref": program_ref,
                "use_latest": True,
            },
            "on": triggers,
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
                "use_latest": True,
                "comment": "Aleph Alpine Linux with Python 3.8",
            },
            "volumes": volumes,
            # {
            #     "mount": "/opt/venv",
            #     "ref": "5f31b0706f59404fad3d0bff97ef89ddf24da4761608ea0646329362c662ba51",
            #     "use_latest": False
            # },
            # {
            #     "comment": "Working data persisted on the VM supervisor, not available on other nodes",
            #     "mount": "/var/lib/sqlite",
            #     "name": "database",
            #     "persistence": "host",
            #     "size_mib": 5
            # }
            "time": time.time(),
        }
    )

    return await submit(
        account=account,
        content=content.dict(exclude_none=True),
        message_type="PROGRAM",
        channel=channel,
        api_server=api_server,
        storage_engine=storage_engine,
        session=session,
        inline=True,
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

    if inline and (len(item_content) < 50000):
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


async def watch_messages(
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
) -> AsyncIterable[Dict[str, Any]]:
    """
    Iterate over current and future matching messages asynchronously.
    """

    session = session or get_fallback_session()

    params: Dict[str, Any] = dict()

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

    # FIXME:
    #  We build the URL manually since aiohttp.ClientSession.ws_connect does not support
    #  the `params` argument at the moment.
    #  Upstream issue: https://github.com/aio-libs/aiohttp/issues/5868
    #  Upstream pull request: https://github.com/aio-libs/aiohttp/pull/5869
    url = URL(f"{api_server}/api/ws0/messages").with_query(params)

    async with session.ws_connect(url) as ws:
        logger.debug("Websocket connected")
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                if msg.data == "close cmd":
                    await ws.close()
                    break
                else:
                    yield json.loads(msg.data)
            elif msg.type == aiohttp.WSMsgType.ERROR:
                break


async def _run_watch_messages(coroutine: AsyncIterable, output_queue: queue.Queue):
    """Forward messages from the coroutine to the synchronous queue"""
    async for message in coroutine:
        output_queue.put(message)


def _start_run_watch_messages(output_queue: queue.Queue, args: List, kwargs: Dict):
    """Thread entrypoint to run the `watch_messages` asynchronous generator in a thread."""
    watcher = watch_messages(*args, **kwargs)
    runner = _run_watch_messages(watcher, output_queue)
    asyncio.new_event_loop().run_until_complete(runner)
