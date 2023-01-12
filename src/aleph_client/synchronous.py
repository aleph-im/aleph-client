import asyncio
import queue
import threading
from typing import (
    Any,
    Callable,
    List,
    Optional,
    Dict,
    Iterable,
    Type,
    Protocol,
    TypeVar,
    Awaitable,
)

from aiohttp import ClientSession
from aleph_message.models import AlephMessage
from aleph_message.models.program import ProgramContent, Encoding

from . import asynchronous
from .conf import settings
from .types import Account, StorageEnum, GenericMessage


T = TypeVar("T")


def wrap_async(func: Callable[..., Awaitable[T]]) -> Callable[..., T]:
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
forget = wrap_async(asynchronous.forget)
ipfs_push = wrap_async(asynchronous.ipfs_push)
storage_push = wrap_async(asynchronous.storage_push)
ipfs_push_file = wrap_async(asynchronous.ipfs_push_file)
storage_push_file = wrap_async(asynchronous.storage_push_file)
create_aggregate = wrap_async(asynchronous.create_aggregate)
create_store = wrap_async(asynchronous.create_store)
submit = wrap_async(asynchronous.submit)
fetch_aggregate = wrap_async(asynchronous.fetch_aggregate)
fetch_aggregates = wrap_async(asynchronous.fetch_aggregates)
get_posts = wrap_async(asynchronous.get_posts)
get_messages = wrap_async(asynchronous.get_messages)


def get_message(
    item_hash: str,
    message_type: Optional[Type[GenericMessage]] = None,
    channel: Optional[str] = None,
    session: Optional[ClientSession] = None,
    api_server: str = settings.API_HOST,
) -> GenericMessage:
    return wrap_async(asynchronous.get_message)(
        item_hash=item_hash,
        message_type=message_type,
        channel=channel,
        session=session,
        api_server=api_server,
    )


def create_program(
    account: Account,
    program_ref: str,
    entrypoint: str,
    runtime: str,
    environment_variables: Optional[Dict[str, str]] = None,
    storage_engine: StorageEnum = StorageEnum.storage,
    channel: Optional[str] = None,
    address: Optional[str] = None,
    session: Optional[ClientSession] = None,
    api_server: Optional[str] = None,
    memory: Optional[int] = None,
    vcpus: Optional[int] = None,
    timeout_seconds: Optional[float] = None,
    persistent: bool = False,
    encoding: Encoding = Encoding.zip,
    volumes: Optional[List[Dict]] = None,
    subscriptions: Optional[List[Dict]] = None,
):
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
    return wrap_async(asynchronous.create_program)(
        account=account,
        program_ref=program_ref,
        entrypoint=entrypoint,
        environment_variables=environment_variables,
        runtime=runtime,
        storage_engine=storage_engine,
        channel=channel,
        address=address,
        session=session,
        api_server=api_server,
        memory=memory,
        vcpus=vcpus,
        timeout_seconds=timeout_seconds,
        persistent=persistent,
        encoding=encoding,
        volumes=volumes,
        subscriptions=subscriptions,
    )


def watch_messages(*args, **kwargs) -> Iterable[AlephMessage]:
    """
    Iterate over current and future matching messages synchronously.

    Runs the `watch_messages` asynchronous generator in a thread.
    """
    output_queue: queue.Queue[AlephMessage] = queue.Queue()
    thread = threading.Thread(
        target=asynchronous._start_run_watch_messages, args=(output_queue, args, kwargs)
    )
    thread.start()
    while True:
        yield output_queue.get()
