.. _aggregates:

==========
Aggregates
==========

Aggregates are a key-value store specific to an account.
Each time a new aggregate message is received for a specific account, the
nodes update the aggregate for this account.

Like a dictionary update, if a key already exists, it is updated,
otherwise it is created.

Query aggregate of an account
-----------------------------

To query keys from an account aggregate, you need to call the
fetch_aggregate function on the client.

Since version 0.8.0, only the asynchronous methods are available.
To use them in the Python REPL, simply start it with:

.. code-block:: bash

    $ python3 -m asyncio

Then you can use the asynchronous methods:

.. code-block:: python3

    >>> from aleph.sdk.client import AlephHttpClient
    >>> async with AlephHttpClient() as client:
    ...     await client.fetch_aggregate(
    ...         "0x06DE0C46884EbFF46558Cd1a9e7DA6B1c3E9D0a8",
    ...         "profile",
    ...     )
    {"bio": "tester", "name": "Moshe on Ethereum"}


Mutate aggregate
----------------

To mutate an aggregate you need to call the create_aggregate function (it will
create an AGGREGATE type message for you and submit it).

You need a valid account and instantiate an authenticated client:

.. code-block:: python3

    >>> from aleph.sdk.chains.ethereum import get_fallback_account
    >>> from aleph.sdk.client import AuthenticatedAlephHttpClient
    >>> account = get_fallback_account()
    >>> async with AuthenticatedAlephHttpClient(account) as client:
    ...     message, status = await client.create_aggregate(
    ...         "profile",
    ...         {"bio": "tester", "name": "Moshe on Ethereum"},
    ...     )
    >>> message.content
    {
        'key': 'profile',
        'content': {'bio': 'tester', 'name': 'Moshe on Ethereum'},
        'address': '0x...',
        'time': 1689081614.4252806,
    }


Delegate write access to an aggregate key
-----------------------------------------

If you want to set an aggregate on another address than the one of your
account, this address should have something similar to this in its
"security" key:

.. code-block:: python3

    >>> async with AuthenticatedAlephHttpClient(account) as client:
    >>>     await client.fetch_aggregate('YOUR_ADDRESS', 'security')
    {'authorizations': [
        {
            'address': 'TARGET_ADDRESS',
            'types': ['AGGREGATE]
            'aggregate_keys': ['testkey']
        }
    ]}

The owner of TARGET_ADDRESS can then set content of the "testkey" key of
YOUR_ADDRESS's aggregate:

.. code-block:: python3

    >>> async with AuthenticatedAlephHttpClient(account) as client:
    ...     # Assuming 'account' is TARGET_ADDRESS
    ...     message, status = await client.create_aggregate(
    ...         "testkey",
    ...         {"access": "alien"},
    ...         address="YOUR_ADDRESS",
    ...     )
    >>> message.content
    {
        'key': 'testkey',
        'content': {"access": "alien"},
        'address': 'TARGET_ADDRESS',
        'time': 1689081614.4252806,
    }


.. note::

    For more information on the authorizations model, see
    `this pyaleph doc
    <https://pyaleph.readthedocs.io/en/latest/protocol/authorizations.html>`_.
