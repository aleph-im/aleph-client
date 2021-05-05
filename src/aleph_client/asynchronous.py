""" This is the simplest aleph network client available.
"""
from binascii import hexlify
import time
from typing import Optional

import aiohttp
import asyncio
import json
import hashlib

from aleph_client.chains.common import BaseAccount
from aleph_message import Message

DEFAULT_SERVER = "https://api1.aleph.im"
DEFAULT_SERVER = "http://163.172.70.92:4024"

FALLBACK_SESSION = None


async def get_fallback_session() -> aiohttp.ClientSession:
    global FALLBACK_SESSION
    if FALLBACK_SESSION is None:
        FALLBACK_SESSION = aiohttp.ClientSession()
    return FALLBACK_SESSION


def wrap_async(func):
    def func_caller(*args, **kwargs):
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(func(*args, **kwargs))

    return func_caller


async def ipfs_push(content, session=None, api_server=DEFAULT_SERVER):
    if session is None:
        session = await get_fallback_session()

    async with session.post(
        f"{api_server}/api/v0/ipfs/add_json", json=content
    ) as resp:
        resp.raise_for_status()
        return (await resp.json()).get("hash")


sync_ipfs_push = wrap_async(ipfs_push)


async def storage_push(content, session=None, api_server=DEFAULT_SERVER):
    if session is None:
        session = await get_fallback_session()

    async with session.post(
        f"{api_server}/api/v0/storage/add_json", json=content
    ) as resp:
        resp.raise_for_status()
        return (await resp.json()).get("hash")


sync_storage_push = wrap_async(storage_push)


async def ipfs_push_file(file_content, session=None, api_server=DEFAULT_SERVER):
    if session is None:
        session = await get_fallback_session()

    data = aiohttp.FormData()
    data.add_field("file", file_content)

    async with session.post(f"{api_server}/api/v0/ipfs/add_file", data=data) as resp:
        resp.raise_for_status()
        return (await resp.json()).get("hash")


sync_ipfs_push_file = wrap_async(ipfs_push_file)


async def storage_push_file(file_content, session=None, api_server=DEFAULT_SERVER):
    if session is None:
        session = await get_fallback_session()

    data = aiohttp.FormData()
    data.add_field("file", file_content)

    async with session.post(
        f"{api_server}/api/v0/storage/add_file", data=data
    ) as resp:
        resp.raise_for_status()
        return (await resp.json()).get("hash")


sync_storage_push_file = wrap_async(storage_push_file)


async def broadcast(message: dict, session: Optional[aiohttp.ClientSession]=None,
                    api_server=DEFAULT_SERVER):

    session: aiohttp.ClientSession = session or await get_fallback_session()

    async with session.post(
        f"{api_server}/api/v0/ipfs/pubsub/pub",
        json={"topic": "ALEPH-TEST", "data": json.dumps(message)},
    ) as resp:
        resp.raise_for_status()
        return (await resp.json()).get("value")


sync_broadcast = wrap_async(broadcast)


async def create_post(
    account: BaseAccount,
    post_content,
    post_type,
    ref=None,
    address=None,
    channel="TEST",
    session=None,
    api_server=DEFAULT_SERVER,
    inline=True,
    storage_engine="storage",
):
    if address is None:
        address = account.get_address()

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
    account,
    key,
    content,
    address=None,
    channel="TEST",
    session=None,
    api_server=DEFAULT_SERVER,
):
    if address is None:
        address = account.get_address()

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
    account,
    address=None,
    file_content=None,
    file_hash=None,
    storage_engine="storage",
    extra_fields=None,
    channel="TEST",
    session=None,
    api_server=DEFAULT_SERVER,
):
    if address is None:
        address = account.get_address()

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


async def submit(
    account: BaseAccount,
    content,
    message_type,
    channel="IOT_TEST",
    api_server=DEFAULT_SERVER,
    storage_engine="storage",
    session=None,
    inline=True,
):
    message = Message(
        #'item_hash': ipfs_hash,
        chain= account.CHAIN,
        channel=channel,
        sender=account.get_address(),
        type=message_type,
        time=time.time(),
    )

    item_content = json.dumps(content, separators=(",", ":"))

    if inline and (len(item_content) < 100000):
        message.item_content = item_content
        h = hashlib.sha256()
        h.update(message.item_content.encode("utf-8"))
        message.item_hash = h.hexdigest()
    else:
        if storage_engine == "ipfs":
            message.item_hash = await ipfs_push(content, api_server=api_server)
        else:  # storage
            message.item_hash = await storage_push(content, api_server=api_server)

    message_dict: dict = account.sign_message(message.dict())
    await broadcast(message_dict, session=session, api_server=api_server)

    # let's add the content to the object so users can access it.
    message_dict["content"] = content
    return message_dict


sync_submit = wrap_async(submit)


async def fetch_aggregate(address, key, session=None, api_server=DEFAULT_SERVER):
    if session is None:
        session = await get_fallback_session()

    async with session.get(
        f"{api_server}/api/v0/aggregates/{address}.json?keys={key}"
    ) as resp:
        return (await resp.json()).get("data", dict()).get(key)


sync_fetch_aggregate = wrap_async(fetch_aggregate)


async def get_posts(
    pagination=200,
    page=1,
    types=None,
    refs=None,
    addresses=None,
    tags=None,
    hashes=None,
    channels=None,
    start_date=None,
    end_date=None,
    session=None,
    api_server=DEFAULT_SERVER,
):
    if session is None:
        session = await get_fallback_session()

    params = dict(pagination=pagination, page=page)

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
        if hasattr(start_date, "timestamp"):
            start_date = start_date.timestamp()
        params["start_date"] = start_date
    if end_date is not None:
        if hasattr(end_date, "timestamp"):
            end_date = end_date.timestamp()
        params["end_date"] = end_date

    async with session.get(
        f"{api_server}/api/v0/posts.json", params=params
    ) as resp:
        resp.raise_for_status()
        return await resp.json()


sync_get_posts = wrap_async(get_posts)


async def get_messages(
    pagination=200,
    page=1,
    message_type=None,
    content_types=None,
    refs=None,
    addresses=None,
    tags=None,
    hashes=None,
    channels=None,
    start_date=None,
    end_date=None,
    session=None,
    api_server=DEFAULT_SERVER,
):
    if session is None:
        session = await get_fallback_session()

    params = dict(pagination=pagination, page=page)

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
        if hasattr(start_date, "timestamp"):
            start_date = start_date.timestamp()
        params["start_date"] = start_date
    if end_date is not None:
        if hasattr(end_date, "timestamp"):
            end_date = end_date.timestamp()
        params["end_date"] = end_date

    async with session.get(
        f"{api_server}/api/v0/messages.json", params=params
    ) as resp:
        resp.raise_for_status()
        return await resp.json()


sync_get_messages = wrap_async(get_messages)
