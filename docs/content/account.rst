Accounts
========

To send data to the aleph.im network, you need to have an account.
This account can be made using any of the supported providers.

Common
------

You will need to instanciate an account using a private key accepted by the
corresponding account provider.

If you don't want to handle the private key yourself, you can use the
"fallback" helper. This searches for a "device.key" file in the current folder.
If this file isn't found, it will try to create a new key file with a random
key.

Ethereum
********

Example using Ethereum:

.. code-block:: python3

    from aleph_client.chains.ethereum import get_fallback_account

    account = get_fallback_account()

Another example setting the private key manually:

.. code-block:: python3

    from aleph_client.chains.ethereum import ETHAccount

    prv = bytes.fromhex("xxxxxx")

    account = ETHAccount(prv)

Depending on account provider, the key can be passed as an hex string.
It's the case for Ethereum:

.. code-block:: python3

    >>> from aleph_client.chains.ethereum import ETHAccount
    >>> account = ETHAccount("0x0000000000000000000000000000000000000000000000000000000000000001")
    >>> account.get_address()
    '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf'

.. WARNING::
    Do not use this dummy private key, it's just an example!

Polkadot / Substrate
********************

DOT/Substrate accounts are a bit different. You pass them mnemonics, and optionally an address_type.

Example using Substrate (if you already used a fallback on ethereum or nuls, you might consider deleting the private key file):

.. code-block:: python3

    from aleph_client.chains.substrate import get_fallback_account

    account = get_fallback_account()

Another example setting the mnemonics manually:

.. code-block:: python3

    from aleph_client.chains.substrate import DOTAccount

    account = DOTAccount("payment shy team bargain chest fold bless artwork identify breeze pelican category")

.. WARNING::
    Do not use this dummy private key, it's just an example!

You can also change the address_type (0 for polkadot, 2 for canary, 42 generic...).

.. code-block:: python3

    >>> from aleph_client.chains.substrate import DOTAccount
    >>> account = DOTAccount("payment shy team bargain chest fold bless artwork identify breeze pelican category")
    >>> account.get_address()
    '5CGNMKCscqN2QNcT7Jtuz23ab7JUxh8wTEtXhECZLJn5vCGX'
    >>> account = DOTAccount("payment shy team bargain chest fold bless artwork identify breeze pelican category",
    ...                      address_type=0)
    >>> account.get_address()
    '1CfVeTwUcdVqucy4wwv8AsjSjJ8ezh5Xjd1rXButPoc6WJY'

.. WARNING::
    Do not use this dummy private key, it's just an example!

NULS
****

The NULS provider is very similar.

Fallback account:

.. code-block:: python3

    from aleph_client.chains.nuls2 import get_fallback_account

    account = get_fallback_account()

From a private key:

.. code-block:: python3

    >>> from aleph_client.chains.nuls2 import NULSAccount
    >>> account = NULSAccount(
    ...    bytes.fromhex(
    ...    "0000000000000000000000000000000000000000000000000000000000000001"))
    >>> account.get_address()
    'NULSd6Hgb53vAd7ZMoA2E17DUTT4C1nGrJVpn'