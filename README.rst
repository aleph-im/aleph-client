============
aleph-client
============

Python Client for the aleph.im network, next generation network of decentralized big data applications.
Developement follows the `Aleph Whitepaper <https://github.com/aleph-im/aleph-whitepaper>`_.

Documentation
=============

Documentation (albeit still vastly incomplete as it is a work in progress) can be found at http://aleph-client.readthedocs.io/ or built from this repo with:

    $ python setup.py docs


Requirements
============

Some cryptographic functionalities use curve secp256k1 and require installing
`libsecp256k1 <https://github.com/bitcoin-core/secp256k1>`_.

    $ apt-get install -y python3-pip libsecp256k1-dev


Installation
============

Using pip and `PyPI <https://pypi.org/project/aleph-client/>`_:

    $ pip install aleph-client


Installation for development
============================

If you want NULS2 support you will need to install nuls2-python (currently only available on github):

    $ pip install git+https://github.com/aleph-im/nuls2-python.git


To install from source and still be able to modify the source code:

    $ pip install -e .
    or
    $ python setup.py develop
