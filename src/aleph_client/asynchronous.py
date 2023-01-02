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
from typing import Type

from aleph_message.models import (
    ForgetContent,
    MessageType,
    AggregateContent,
    PostContent,
    StoreContent,
    PostMessage,
    Message,
    ForgetMessage,
    AlephMessage,
    AggregateMessage,
    StoreMessage,
    ProgramMessage, ItemType,
)
from pydantic import ValidationError

from aleph_client.types import Account, StorageEnum, GenericMessage
from .exceptions import MessageNotFoundError, MultipleMessagesError
from .models import MessagesResponse
from .utils import get_message_type_value

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
        content: Dict,
        session: ClientSession,
        api_server: str,
) -> str:
    """Push arbitrary content as JSON to the IPFS service."""
    url = f"{api_server}/api/v0/ipfs/add_json"
    logger.debug(f"Pushing to IPFS on {url}")

    async with session.post(url, json=content) as resp:
        resp.raise_for_status()
        return (await resp.json()).get("hash")


async def storage_push(
        content: Dict,
        session: ClientSession,
        api_server: str,
) -> str:
    """Push arbitrary content as JSON to the storage service."""
    url = f"{api_server}/api/v0/storage/add_json"
    logger.debug(f"Pushing to storage on {url}")

    async with session.post(url, json=content) as resp:
        resp.raise_for_status()
        return (await resp.json()).get("hash")


async def ipfs_push_file(
        file_content,
        session: ClientSession,
        api_server: str,
) -> str:
    """Push a file to the IPFS service."""
    data = aiohttp.FormData()
    data.add_field("file", file_content)

    url = f"{api_server}/api/v0/ipfs/add_file"
    logger.debug(f"Pushing file to IPFS on {url}")

    async with session.post(url, data=data) as resp:
        resp.raise_for_status()
        return (await resp.json()).get("hash")


async def storage_push_file(
        file_content,
        session: ClientSession,
        api_server: str,
) -> str:
    """Push a file to the storage service."""
    data = aiohttp.FormData()
    data.add_field("file", file_content)

    url = f"{api_server}/api/v0/storage/add_file"
    logger.debug(f"Posting file on {url}")

    async with session.post(url, data=data) as resp:
        resp.raise_for_status()
        return (await resp.json()).get("hash")


async def broadcast(
        message,
        session: ClientSession,
        api_server: str,
) -> None:
    """Broadcast a message on the Aleph network via pubsub for nodes to pick it up."""
    url = f"{api_server}/api/v0/ipfs/pubsub/pub"
    logger.debug(f"Posting message on {url}")

    async with session.post(
            url,
            json={"topic": "ALEPH-TEST", "data": json.dumps(message)},
    ) as response:
        response.raise_for_status()
        result = await response.json()
        status = result.get("status")
        if status == "success":
            return
        elif status == "warning":
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
        else:
            raise ValueError(
                f"Invalid response from server, status in missing or unknown: '{status}'"
            )


async def create_post(
        account: Account,
        post_content,
        post_type: str,
        ref: Optional[str] = None,
        address: Optional[str] = None,
        channel: Optional[str] = None,
        session: Optional[ClientSession] = None,
        api_server: Optional[str] = None,
        inline: Optional[bool] = None,
        storage_engine: Optional[StorageEnum] = None,
) -> PostMessage:
    """
    Create a POST message on the Aleph network. It is associated with a channel and owned by an account.

    :param account: The account that will sign and own the message
    :param post_content: The content of the message
    :param post_type: An arbitrary content type that helps to describe the post_content
    :param ref: A reference to a previous message that it replaces
    :param address: The address that will be displayed as the author of the message
    :param channel: The channel that the message will be posted on
    :param session: An optional aiohttp session to use for the request
    :param api_server: An optional API server to use for the request (DEFAULT: "https://api2.aleph.im")
    :param inline: An optional flag to indicate if the content should be inlined in the message or not
    :param storage_engine: An optional storage engine to use for the message, if not inlined (DEFAULT: "storage")
    """
    address = address or settings.ADDRESS_TO_USE or account.get_address()

    content = PostContent(
        type=post_type,
        address=address,
        content=post_content,
        time=time.time(),
        ref=ref,
    )

    return await submit(
        account=account,
        content=content.dict(exclude_none=True),
        message_type=MessageType.post,
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
        address: Optional[str] = None,
        channel: Optional[str] = None,
        session: Optional[ClientSession] = None,
        api_server: Optional[str] = None,
        inline: Optional[bool] = None,
) -> AggregateMessage:
    """
    Create an AGGREGATE message. It is meant to be used as a quick access storage associated with an account.

    :param account: Account to use to sign the message
    :param key: Key to use to store the content
    :param content: Content to store
    :param address: Address to use to sign the message
    :param channel: Channel to use (DEFAULT: "TEST")
    :param session: Session to use (DEFAULT: get_fallback_session())
    :param api_server: API server to use (DEFAULT: "https://api2.aleph.im")
    :param inline: Whether to write content inside the message (DEFAULT: True)
    """
    address = address or settings.ADDRESS_TO_USE or account.get_address()

    content_ = AggregateContent(
        key=key,
        address=address,
        content=content,
        time=time.time(),
    )

    return await submit(
        account=account,
        content=content_.dict(exclude_none=True),
        message_type=MessageType.aggregate,
        channel=channel,
        api_server=api_server,
        session=session,
        inline=inline,
    )


async def create_store(
        account: Account,
        address: Optional[str] = None,
        file_content: Optional[bytes] = None,
        file_path: Optional[str] = None,
        file_hash: Optional[str] = None,
        guess_mime_type: Optional[bool] = None,
        ref: Optional[str] = None,
        storage_engine: Optional[StorageEnum] = None,
        extra_fields: Optional[dict] = None,
        channel: Optional[str] = None,
        session: Optional[ClientSession] = None,
        api_server: Optional[str] = None,
) -> StoreMessage:
    """
    Create a STORE message to store a file on the Aleph network.

    Can be passed either a file path, an IPFS hash or the file's content as raw bytes.

    :param account: Account to use to sign the message
    :param address: Address to display as the author of the message (DEFAULT: account.get_address())
    :param file_content: Byte stream of the file to store (DEFAULT: None)
    :param file_path: Path to the file to store (DEFAULT: None)
    :param file_hash: Hash of the file to store (DEFAULT: None)
    :param guess_mime_type: Guess the MIME type of the file (DEFAULT: False)
    :param ref: Reference to a previous message (DEFAULT: None)
    :param storage_engine: Storage engine to use (DEFAULT: "storage")
    :param extra_fields: Extra fields to add to the STORE message (DEFAULT: None)
    :param channel: Channel to post the message to (DEFAULT: "TEST")
    :param session: aiohttp session to use (DEFAULT: get_fallback_session())
    :param api_server: Aleph API server to use (DEFAULT: "https://api2.aleph.im")
    """
    address = address or settings.ADDRESS_TO_USE or account.get_address()
    guess_mime_type = False if guess_mime_type is None else guess_mime_type
    storage_engine = storage_engine or settings.DEFAULT_STORAGE_ENGINE
    extra_fields = extra_fields or {}
    api_server = api_server or settings.API_HOST

    if file_hash is None:
        if file_content is None:
            if file_path is None:
                raise ValueError("Please specify at least a file_content, a file_hash or a file_path")
            else:
                file_content = open(file_path, "rb").read()

        if storage_engine == StorageEnum.storage:
            file_hash = await storage_push_file(
                file_content, session=session, api_server=api_server
            )
        elif storage_engine == StorageEnum.ipfs:
            file_hash = await ipfs_push_file(
                file_content, session=session, api_server=api_server
            )
        else:
            raise ValueError(f"Unknown storage engine: '{storage_engine}'")

    assert file_hash, "File hash should be empty"

    if magic is None:
        pass
    elif file_content and guess_mime_type and ("mime_type" not in extra_fields):
        extra_fields["mime_type"] = magic.from_buffer(file_content, mime=True)

    if ref:
        extra_fields["ref"] = ref

    values = {
        "address": address,
        "item_type": storage_engine,
        "item_hash": file_hash,
        "time": time.time(),
    }
    if extra_fields is not None:
        values.update(extra_fields)

    content = StoreContent(**values)

    return await submit(
        account=account,
        content=content.dict(exclude_none=True),
        message_type=MessageType.store,
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
        environment_variables: Optional[Dict[str, str]] = None,
        storage_engine: Optional[StorageEnum] = None,
        channel: Optional[str] = None,
        address: Optional[str] = None,
        session: Optional[ClientSession] = None,
        api_server: Optional[str] = None,
        memory: Optional[int] = None,
        vcpus: Optional[int] = None,
        timeout_seconds: Optional[float] = None,
        persistent: Optional[bool] = None,
        encoding: Optional[Encoding] = None,
        volumes: Optional[List[Dict]] = None,
        subscriptions: Optional[List[Dict]] = None,
) -> ProgramMessage:
    """
    Post a (create) PROGRAM message.

    :param account: Account to use to sign the message
    :param program_ref: Reference to the program to run
    :param entrypoint: Entrypoint to run
    :param runtime: Runtime to use
    :param environment_variables: Environment variables to pass to the program
    :param storage_engine: Storage engine to use (DEFAULT: "storage")
    :param channel: Channel to use (DEFAULT: "TEST")
    :param address: Address to use (DEFAULT: account.get_address())
    :param session: Session to use (DEFAULT: get_fallback_session())
    :param api_server: API server to use (DEFAULT: "https://api2.aleph.im")
    :param memory: Memory in MB for the VM to be allocated (DEFAULT: 128)
    :param vcpus: Number of vCPUs to allocate (DEFAULT: 1)
    :param timeout_seconds: Timeout in seconds (DEFAULT: 30.0)
    :param persistent: Whether the program should be persistent or not (DEFAULT: False)
    :param encoding: Encoding to use (DEFAULT: Encoding.zip)
    :param volumes: Volumes to mount
    :param subscriptions: Patterns of Aleph messages to forward to the program's event receiver
    """
    storage_engine = storage_engine or settings.DEFAULT_STORAGE_ENGINE
    address = address or settings.ADDRESS_TO_USE or account.get_address()
    volumes = volumes if volumes is not None else []
    memory = memory or settings.DEFAULT_VM_MEMORY
    vcpus = vcpus or settings.DEFAULT_VM_VCPUS
    timeout_seconds = timeout_seconds or settings.DEFAULT_VM_TIMEOUT
    persistent = False if persistent is None else persistent
    encoding = encoding or Encoding.zip

    # TODO: Check that program_ref, runtime and data_ref exist

    # Register the different ways to trigger a VM
    if subscriptions:
        # Trigger on HTTP calls and on Aleph message subscriptions.
        triggers = {"http": True, "persistent": persistent, "message": subscriptions}
    else:
        # Trigger on HTTP calls.
        triggers = {"http": True, "persistent": persistent}

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
            "variables": environment_variables,
            "resources": {
                "vcpus": vcpus,
                "memory": memory,
                "seconds": timeout_seconds,
            },
            "runtime": {
                "ref": runtime,
                "use_latest": True,
                "comment": "Official Aleph runtime"
                if runtime == settings.DEFAULT_RUNTIME_ID
                else "",
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

    # Ensure that the version of aleph-message used supports the field.
    assert content.on.persistent == persistent

    return await submit(
        account=account,
        content=content.dict(exclude_none=True),
        message_type=MessageType.program,
        channel=channel,
        api_server=api_server,
        storage_engine=storage_engine,
        session=session,
    )


async def forget(
        account: Account,
        hashes: List[str],
        reason: Optional[str],
        storage_engine: Optional[StorageEnum] = None,
        channel: Optional[str] = None,
        address: Optional[str] = None,
        session: Optional[ClientSession] = None,
        api_server: Optional[str] = None,
) -> ForgetMessage:
    """
    Post a FORGET message to remove previous messages from the network.

    Targeted messages need to be signed by the same account that is attempting to forget them,
    if the creating address did not delegate the access rights to the forgetting account.

    :param account: Account to use to sign the message
    :param hashes: Hashes of the messages to forget
    :param reason: Reason for forgetting the messages
    :param storage_engine: Storage engine to use (DEFAULT: "storage")
    :param channel: Channel to use (DEFAULT: "TEST")
    :param address: Address to use (DEFAULT: account.get_address())
    :param session: Session to use (DEFAULT: get_fallback_session())
    :param api_server: API server to use (DEFAULT: "https://api2.aleph.im")
    """
    address = address or settings.ADDRESS_TO_USE or account.get_address()

    content = ForgetContent(
        hashes=hashes,
        reason=reason,
        address=address,
        time=time.time(),
    )

    return await submit(
        account,
        content=content.dict(exclude_none=True),
        message_type=MessageType.forget,
        channel=channel,
        api_server=api_server,
        storage_engine=storage_engine,
        session=session
    )


async def submit(
        account: Account,
        content: Dict,
        message_type: MessageType,
        channel: Optional[str] = None,
        api_server: Optional[str] = None,
        storage_engine: Optional[StorageEnum] = None,
        session: Optional[ClientSession] = None,
        inline: Optional[bool] = None,
) -> AlephMessage:
    """Main function to post a message to the network. Use the other functions in this module if you can."""
    channel = channel or settings.DEFAULT_CHANNEL
    api_server = api_server or settings.API_HOST
    storage_engine = storage_engine or settings.DEFAULT_STORAGE_ENGINE
    session = session or get_fallback_session()
    inline = True if inline is None else inline

    message: Dict[str, Any] = {
        # 'item_hash': ipfs_hash,
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
        message["item_type"] = ItemType.inline
    else:
        if storage_engine == StorageEnum.ipfs:
            message["item_hash"] = await ipfs_push(
                content, session=session, api_server=api_server
            )
            message["item_type"] = ItemType.ipfs
        else:  # storage
            assert storage_engine == StorageEnum.storage
            message["item_hash"] = await storage_push(
                content, session=session, api_server=api_server
            )
            message["item_type"] = ItemType.storage

    message = await account.sign_message(message)
    await broadcast(message, session=session, api_server=api_server)

    # let's add the content to the object so users can access it.
    message["content"] = content

    return Message(**message)


async def fetch_aggregate(
        address: str,
        key: str,
        limit: Optional[int] = None,
        session: Optional[ClientSession] = None,
        api_server: Optional[str] = None,
) -> Dict[str, Dict]:
    """
    Fetch a value from the aggregate store by owner address and item key.

    :param address: Address of the owner of the aggregate
    :param key: Key of the aggregate
    :param limit: Maximum number of items to fetch (DEFAULT: 100)
    :param session: Session to use (DEFAULT: get_fallback_session())
    :param api_server: API server to use (DEFAULT: "https://api2.aleph.im")
    """
    limit = limit or 100
    session = session or get_fallback_session()
    api_server = api_server or settings.API_HOST

    params: Dict[str, Any] = {"keys": key}
    if limit:
        params["limit"] = limit

    async with session.get(
            f"{api_server}/api/v0/aggregates/{address}.json", params=params
    ) as resp:
        result = await resp.json()
        data = result.get("data", dict())
        return data.get(key)


async def fetch_aggregates(
        address: str,
        keys: Optional[Iterable[str]] = None,
        limit: Optional[int] = None,
        session: Optional[ClientSession] = None,
        api_server: Optional[str] = None,
) -> Dict[str, Dict]:
    """
    Fetch key-value pairs from the aggregate store by owner address.

    :param address: Address of the owner of the aggregate
    :param keys: Keys of the aggregates to fetch (DEFAULT: all items)
    :param limit: Maximum number of items to fetch (DEFAULT: 100)
    :param session: Session to use (DEFAULT: get_fallback_session())
    :param api_server: API server to use (DEFAULT: "https://api2.aleph.im")
    """
    limit = limit or 100
    session = session or get_fallback_session()
    api_server = api_server or settings.API_HOST

    keys_str = ",".join(keys) if keys else ""
    params: Dict[str, Any] = {}
    if keys_str:
        params["keys"] = keys_str
    if limit:
        params["limit"] = limit

    async with session.get(
            f"{api_server}/api/v0/aggregates/{address}.json",
            params=params,
    ) as resp:
        result = await resp.json()
        data = result.get("data", dict())
        return data


async def get_posts(
        pagination: int = 200,
        page: int = 1,
        types: Optional[Iterable[str]] = None,
        refs: Optional[Iterable[str]] = None,
        addresses: Optional[Iterable[str]] = None,
        tags: Optional[Iterable[str]] = None,
        hashes: Optional[Iterable[str]] = None,
        channels: Optional[Iterable[str]] = None,
        chains: Optional[Iterable[str]] = None,
        start_date: Optional[Union[datetime, float]] = None,
        end_date: Optional[Union[datetime, float]] = None,
        session: Optional[ClientSession] = None,
        api_server: Optional[str] = None,
) -> Dict[str, Dict]:
    """
    Fetch a list of posts from the network.

    :param pagination: Number of items to fetch (DEFAULT: 200)
    :param page: Page to fetch, begins at 1 (DEFAULT: 1)
    :param types: Types of posts to fetch (DEFAULT: all types)
    :param refs: If set, only fetch posts that reference these hashes (in the "refs" field)
    :param addresses: Addresses of the posts to fetch (DEFAULT: all addresses)
    :param tags: Tags of the posts to fetch (DEFAULT: all tags)
    :param hashes: Specific item_hashes to fetch
    :param channels: Channels of the posts to fetch (DEFAULT: all channels)
    :param chains: Chains of the posts to fetch (DEFAULT: all chains)
    :param start_date: Earliest date to fetch messages from
    :param end_date: Latest date to fetch messages from
    :param session: Session to use (DEFAULT: get_fallback_session())
    :param api_server: API server to use (DEFAULT: "https://api2.aleph.im")
    """
    session = session or get_fallback_session()
    api_server = api_server or settings.API_HOST

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
    if chains is not None:
        params["chains"] = ",".join(chains)

    if start_date is not None:
        if not isinstance(start_date, float) and hasattr(start_date, "timestamp"):
            start_date = start_date.timestamp()
        params["startDate"] = start_date
    if end_date is not None:
        if not isinstance(end_date, float) and hasattr(start_date, "timestamp"):
            end_date = end_date.timestamp()
        params["endDate"] = end_date

    async with session.get(f"{api_server}/api/v0/posts.json", params=params) as resp:
        resp.raise_for_status()
        return await resp.json()


async def get_messages(
        pagination: int = 200,
        page: int = 1,
        message_type: Optional[MessageType] = None,
        content_types: Optional[Iterable[str]] = None,
        content_keys: Optional[Iterable[str]] = None,
        refs: Optional[Iterable[str]] = None,
        addresses: Optional[Iterable[str]] = None,
        tags: Optional[Iterable[str]] = None,
        hashes: Optional[Iterable[str]] = None,
        channels: Optional[Iterable[str]] = None,
        chains: Optional[Iterable[str]] = None,
        start_date: Optional[Union[datetime, float]] = None,
        end_date: Optional[Union[datetime, float]] = None,
        session: Optional[ClientSession] = None,
        api_server: Optional[str] = None,
        ignore_invalid_messages: Optional[bool] = None,
        invalid_messages_log_level: Optional[int] = None,
) -> MessagesResponse:
    """
    Fetch a list of messages from the network.

    :param pagination: Number of items to fetch (DEFAULT: 200)
    :param page: Page to fetch, begins at 1 (DEFAULT: 1)
    :param message_type: Filter by message type, can be "AGGREGATE", "POST", "PROGRAM", "VM", "STORE" or "FORGET"
    :param content_types: Filter by content type
    :param content_keys: Filter by content key
    :param refs: If set, only fetch posts that reference these hashes (in the "refs" field)
    :param addresses: Addresses of the posts to fetch (DEFAULT: all addresses)
    :param tags: Tags of the posts to fetch (DEFAULT: all tags)
    :param hashes: Specific item_hashes to fetch
    :param channels: Channels of the posts to fetch (DEFAULT: all channels)
    :param chains: Filter by sender address chain
    :param start_date: Earliest date to fetch messages from
    :param end_date: Latest date to fetch messages from
    :param session: Session to use (DEFAULT: get_fallback_session())
    :param api_server: API server to use (DEFAULT: "https://api2.aleph.im")
    :param ignore_invalid_messages: Ignore invalid messages (DEFAULT: False)
    :param invalid_messages_log_level: Log level to use for invalid messages (DEFAULT: logging.NOTSET)
    """
    session = session or get_fallback_session()
    api_server = api_server or settings.API_HOST
    ignore_invalid_messages = True if ignore_invalid_messages is None else ignore_invalid_messages
    invalid_messages_log_level = logging.NOTSET if invalid_messages_log_level is None else invalid_messages_log_level

    params: Dict[str, Any] = dict(pagination=pagination, page=page)

    if message_type is not None:
        params["msgType"] = message_type.value
    if content_types is not None:
        params["contentTypes"] = ",".join(content_types)
    if content_keys is not None:
        params["contentKeys"] = ",".join(content_keys)
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
    if chains is not None:
        params["chains"] = ",".join(chains)

    if start_date is not None:
        if not isinstance(start_date, float) and hasattr(start_date, "timestamp"):
            start_date = start_date.timestamp()
        params["startDate"] = start_date
    if end_date is not None:
        if not isinstance(end_date, float) and hasattr(start_date, "timestamp"):
            end_date = end_date.timestamp()
        params["endDate"] = end_date

    async with session.get(f"{api_server}/api/v0/messages.json", params=params) as resp:
        resp.raise_for_status()
        response_json = await resp.json()
        messages_raw = response_json["messages"]

        # All messages may not be valid according to the latest specification in
        # aleph-message. This allows the user to specify how errors should be handled.
        messages: List[AlephMessage] = []
        for message_raw in messages_raw:
            try:
                message = Message(**message_raw)
                messages.append(message)
            except KeyError as e:
                if not ignore_invalid_messages:
                    raise e
                logger.log(
                    level=invalid_messages_log_level,
                    msg=f"KeyError: Field '{e.args[0]}' not found",
                )
            except ValidationError as e:
                if not ignore_invalid_messages:
                    raise e
                if invalid_messages_log_level:
                    logger.log(level=invalid_messages_log_level, msg=e)

        return MessagesResponse(
            messages=messages,
            pagination_page=response_json["pagination_page"],
            pagination_total=response_json["pagination_total"],
            pagination_per_page=response_json["pagination_per_page"],
            pagination_item=response_json["pagination_item"],
        )


async def get_message(
        item_hash: str,
        message_type: Optional[Type[GenericMessage]] = None,
        channel: Optional[str] = None,
        session: Optional[ClientSession] = None,
        api_server: Optional[str] = None,
) -> GenericMessage:
    """
    Get a single message from its `item_hash` and perform some basic validation.

    :param item_hash: Hash of the message to fetch
    :param message_type: Type of message to fetch
    :param channel: Channel of the message to fetch
    :param session: Session to use (DEFAULT: get_fallback_session())
    :param api_server: API server to use (DEFAULT: "https://api2.aleph.im")
    """
    messages_response = await get_messages(
        hashes=[item_hash],
        session=session,
        channels=[channel] if channel else None,
        api_server=api_server,
    )
    if len(messages_response.messages) < 1:
        raise MessageNotFoundError(f"No such hash {item_hash}")
    if len(messages_response.messages) != 1:
        raise MultipleMessagesError(
            f"Multiple messages found for the same item_hash `{item_hash}`"
        )
    message: GenericMessage = messages_response.messages[0]
    if message_type:
        expected_type = get_message_type_value(message_type)
        if message.type != expected_type:
            raise TypeError(
                f"The message type '{message.type}' "
                f"does not match the expected type '{expected_type}'"
            )
    return message


async def watch_messages(
        message_type: Optional[MessageType] = None,
        content_types: Optional[Iterable[str]] = None,
        refs: Optional[Iterable[str]] = None,
        addresses: Optional[Iterable[str]] = None,
        tags: Optional[Iterable[str]] = None,
        hashes: Optional[Iterable[str]] = None,
        channels: Optional[Iterable[str]] = None,
        chains: Optional[Iterable[str]] = None,
        start_date: Optional[Union[datetime, float]] = None,
        end_date: Optional[Union[datetime, float]] = None,
        session: Optional[ClientSession] = None,
        api_server: Optional[str] = None,
) -> AsyncIterable[AlephMessage]:
    """
    Iterate over current and future matching messages asynchronously.

    :param message_type: Type of message to watch
    :param content_types: Content types to watch
    :param refs: References to watch
    :param addresses: Addresses to watch
    :param tags: Tags to watch
    :param hashes: Hashes to watch
    :param channels: Channels to watch
    :param chains: Chains to watch
    :param start_date: Start date from when to watch
    :param end_date: End date until when to watch
    :param session: Session to use (DEFAULT: get_fallback_session())
    :param api_server: API server to use (DEFAULT: "https://api2.aleph.im")
    """
    session = session or get_fallback_session()
    api_server = api_server or settings.API_HOST

    params: Dict[str, Any] = dict()

    if message_type is not None:
        params["msgType"] = message_type.value
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
    if chains is not None:
        params["chains"] = ",".join(chains)

    if start_date is not None:
        if not isinstance(start_date, float) and hasattr(start_date, "timestamp"):
            start_date = start_date.timestamp()
        params["startDate"] = start_date
    if end_date is not None:
        if not isinstance(end_date, float) and hasattr(start_date, "timestamp"):
            end_date = end_date.timestamp()
        params["endDate"] = end_date

    async with session.ws_connect(
            f"{api_server}/api/ws0/messages", params=params
    ) as ws:
        logger.debug("Websocket connected")
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                if msg.data == "close cmd":
                    await ws.close()
                    break
                else:
                    data = json.loads(msg.data)
                    yield Message(**data)
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
    asyncio.run(runner)
