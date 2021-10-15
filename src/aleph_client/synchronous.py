import asyncio
import queue
import threading
from typing import List, Optional, Dict

from aiohttp import ClientSession
from aleph_message.models.program import ProgramContent, Encoding  # type: ignore

from . import asynchronous
from .conf import settings
from .types import Account, StorageEnum


def wrap_async(func):
    """Wrap an asynchronous function into a synchronous one,
    for easy use in synchronous code.
    """

    def func_caller(*args, **kwargs):
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(func(*args, **kwargs))

    # Copy wrapped function interface:
    func_caller.__doc__ = func.__doc__
    func_caller.__annotations__ = func.__annotations__
    func_caller.__defaults__ = func.__defaults__
    func_caller.__kwdefaults__ = func.__kwdefaults__
    return func_caller


create_post = wrap_async(asynchronous.create_post)
ipfs_push = wrap_async(asynchronous.ipfs_push)
storage_push = wrap_async(asynchronous.storage_push)
ipfs_push_file = wrap_async(asynchronous.ipfs_push_file)
storage_push_file = wrap_async(asynchronous.storage_push_file)
broadcast = wrap_async(asynchronous.broadcast)
create_aggregate = wrap_async(asynchronous.create_aggregate)
create_store = wrap_async(asynchronous.create_store)
submit = wrap_async(asynchronous.submit)
fetch_aggregate = wrap_async(asynchronous.fetch_aggregate)
fetch_aggregates = wrap_async(asynchronous.fetch_aggregates)
get_posts = wrap_async(asynchronous.get_posts)
get_messages = wrap_async(asynchronous.get_messages)


def create_program(
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
    return wrap_async(asynchronous.create_program)(
        account=account,
        program_ref=program_ref,
        entrypoint=entrypoint,
        runtime=runtime,
        storage_engine=storage_engine,
        channel=channel,
        address=address,
        session=session,
        api_server=api_server,
        memory=memory,
        encoding=encoding,
        volumes=volumes,
        subscriptions=subscriptions,
    )


def watch_messages(*args, **kwargs):
    """
    Iterate over current and future matching messages synchronously.

    Runs the `watch_messages` asynchronous generator in a thread.
    """
    output_queue = queue.Queue()
    thread = threading.Thread(
        target=asynchronous._start_run_watch_messages, args=(output_queue, args, kwargs)
    )
    thread.start()
    while True:
        yield output_queue.get()
