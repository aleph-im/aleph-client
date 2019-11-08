.. _aggregates:

==========
Aggregates
==========

Aggregates are a key-value store specific to an account.
Each time a new aggregate message is received for a specific account, the
nodes add a new layer on top and mutate the global storage for this account.

Query aggregate of an account
-----------------------------

To query keys from an account aggregate, you need to call the fetch_aggregate function.

Synchronous version:

.. code-block:: python3

    >>> from aleph_client.main import fetch_aggregate
    >>> fetch_aggregate("0x06DE0C46884EbFF46558Cd1a9e7DA6B1c3E9D0a8",
    ... "profile")
    {"bio": "tester", "name": "Moshe on Ethereum"} 


Mutate aggregate
----------------

To mutate an aggregate you need to call the create_aggregate function (it will create
an AGGREGATE type message for you and submit it). You need a valid account to do so.

asynchronous version:

.. code-block:: python3

    from aleph_client.main import create_aggregate
        create_aggregate(account)

Asynchronous version:

.. code-block:: python3

    import aiohttp
    from aleph_client.asynchronous import create_aggregate
    async with aiohttp.ClientSession() as session:
        await create_aggregate()