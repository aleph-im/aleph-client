import asyncio
import time
from typing import Awaitable, Callable, TypeVar

T = TypeVar("T")


async def try_until(
    coroutine: Callable[..., Awaitable[T]],
    condition: Callable[[T], bool],
    timeout: float,
    time_between_attempts: float = 0.5,
    *args,
    **kwargs,
) -> T:

    start_time = time.monotonic()

    while time.monotonic() < start_time + timeout:
        result = await coroutine(*args, **kwargs)
        if condition(result):
            return result

        await asyncio.sleep(time_between_attempts)
    else:
        raise TimeoutError(f"No success in {timeout} seconds.")
