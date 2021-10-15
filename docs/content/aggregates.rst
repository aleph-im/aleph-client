.. _aggregates:

==========
Aggregates
==========

Aggregates are a key-value store specific to an account.
Each time a new aggregate message is received for a specific account, the
nodes add a new layer on top and mutate the global storage for this account.

Query aggregate of an account
-----------------------------

To query keys from an account aggregate, you need to call the fetch
aggregate function.

Synchronous version:

.. code-block:: python3

    >>> from aleph_client.synchronous import fetch_aggregate
    >>> fetch_aggregate("0x06DE0C46884EbFF46558Cd1a9e7DA6B1c3E9D0a8",
    ... "profile")
    {"bio": "tester", "name": "Moshe on Ethereum"}


Mutate aggregate
----------------

To mutate an aggregate you need to call the create_aggregate function (it will
create an AGGREGATE type message for you and submit it).
You need a valid account to do so.

asynchronous version (assumes you already have an account instanciated):

.. code-block:: python3

    >>> from aleph_client.synchronous import create_aggregate, fetch_aggregate
    >>> create_aggregate(
    ...    account, 'testkey', {'a': 1, 'b': 2}, channel='MY_CHANNEL')
    >>> fetch_aggregate(account.get_address(), 'testkey')
    {'a': 1, 'b': 2}
    >>> create_aggregate(
    ...    account, 'testkey', {'a': 2, 'c': 4}, channel='MY_CHANNEL')
    >>> fetch_aggregate(account.get_address(), 'testkey')
    {'a': 2, 'b': 2, 'c': 4}

Asynchronous version is very similar:

.. code-block:: python3

    from aleph_client.asynchronous import create_aggregate
    await create_aggregate(...)

If you want to set an aggregate on another address than the one of your
account, this address should have something similar to this in its
"security" key:

.. code-block:: python3

    >>> fetch_aggregate('TARGET_ADDRESS', 'security')
    {'authorizations': [
        {
            'address': 'YOUR_ADDRESS',
            'types': ['AGGREGATE]
            'aggregate_keys': ['testkey']
        }
    ]}

To write to this address 'testkey' aggregate key:

.. code-block:: python3

    >>> create_aggregate(
    ...    account, 'testkey', {'a': 1, 'b': 2}, channel='MY_CHANNEL',
    ...    address='TARGET_ADDRESS')


.. note::

    For more information on the authorizations model, see
    `this pyaleph doc
    <https://pyaleph.readthedocs.io/en/latest/protocol/authorizations.html>`_.
