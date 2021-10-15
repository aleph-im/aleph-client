=============
Async vs Sync
=============

At aleph.im we really like coding using asyncio,
using async/await construct on Python 3.

That being said, we totally understand that you might not
have the same opinion, or that you might not be in a position
to use it.

For this reason, all the functions have an async version
and a sync version. The sync version are actually
calling the async code behing your back (sneaky!) so you might
be careful if you are calling it in an environment where you
already have an asyncio loop used.

Most chain specific code is synchronous, and core aleph.im interaction
might by async.

Sync code have to be imported from :py:mod:`aleph_client.synchronous`,
async code from :py:mod:`aleph_client.asynchronous`, with
same functions names.

aiohttp session
---------------

Most of the rest interface interaction code is based on aiohttp.
For simplicity sake, if there isn't a passed aiohttp session,
the async functions needing it will instanciate one as a singleton
and reuse it.

There is a lot of use cases where you might prefer to use your own version
instead. Most functions will allow you to do so, by passing a session arg.

Example:

.. code-block:: python3

    >>> import aiohttp
    >>> from aleph_client.asynchronous import fetch_aggregate
    >>> async with aiohttp.ClientSession() as session:
    ...     await fetch_aggregate(
    ...         "0x06DE0C46884EbFF46558Cd1a9e7DA6B1c3E9D0a8",
    ...         "profile", session=session)
    ...
    {"bio": "tester", "name": "Moshe on Ethereum"} 

