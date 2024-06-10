# aleph-client

Python Client for the [aleph.im network](https://www.aleph.im), next generation network of
decentralized big data applications. Developement follows the [Aleph
Whitepaper](https://github.com/aleph-im/aleph-whitepaper).

## Documentation

Documentation can be found on https://docs.aleph.im/tools/aleph-client/

## Requirements

### Linux

Some cryptographic functionalities use curve secp256k1 and require
installing [libsecp256k1](https://github.com/bitcoin-core/secp256k1).

> apt-get install -y python3-pip libsecp256k1-dev

### macOs

> brew tap cuber/homebrew-libsecp256k1
> brew install libsecp256k1

## Installation

Using pip and [PyPI](https://pypi.org/project/aleph-client/):

> pip install aleph-client

## Installation for development

If you want NULS2 support you will need to install nuls2-python
(currently only available on github):

> pip install git+https://github.com/aleph-im/nuls2-python.git

To install from source and still be able to modify the source code:

> pip install -e .

## Using Docker

Use the Aleph client and it\'s CLI from within Docker or Podman with:

> docker run --rm -ti -v $(pwd)/<data:/data> ghcr.io/aleph-im/aleph-client/aleph-client:master --help

Warning: This will use an ephemeral key pair that will be discarded when
stopping the container.
