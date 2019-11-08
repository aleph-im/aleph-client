============
aleph-client
============

Python Client for the aleph.im network, next generation network of decentralized big data applications.
Developement follows the [Aleph Whitepaper](https://github.com/aleph-im/aleph-whitepaper).

Documentation (albeit still vastly incomplete as it is a work in progress) can be found at http://aleph-client.readthedocs.io/ or built from this repo with:

    $ python setup.py docs

Description
===========

A longer description of your project goes here...

Installation for development
============================

If you want NULS2 support you will need to install nuls2-python (currently only available on github):

    $ pip install git+https://github.com/aleph-im/nuls2-python.git


To install from source and still be able to modify the source code:

    $ pip install -e .
    or
    $ python setup.py develop

Build
=====