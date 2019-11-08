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

Example using Ethereum:

.. code-block:: python3

    from aleph_client.chains.ethereum import get_fallback_account

    account = get_fallback_account()

Another example setting the private key manually:

.. code-block:: python3

    from aleph_client.chains.ethereum import EthereumAccount

    prv = bytes.fromhex("xxxxxx")

    account = EthereumAccount(prv)
