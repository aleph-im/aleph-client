# aleph-client

Python Client for the [aleph.im network](https://www.aleph.im), next generation network of
decentralized big data applications. Development follows the [Aleph
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

### Windows

The software is not tested on Windows, but should work using 
the Windows Subsystem for Linux (WSL).

## Installation

### From PyPI

Using pip and [PyPI](https://pypi.org/project/aleph-client/):

> pip install aleph-client

### Using a container

Use the Aleph client and it\'s CLI from within Docker or Podman with:

> docker run --rm -ti -v $(pwd)/<data:/data> ghcr.io/aleph-im/aleph-client/aleph-client:master --help

Warning: This will use an ephemeral key pair that will be discarded when
stopping the container

## Installation for development

We recommend using [hatch](https://hatch.pypa.io/) for development.

Hatch is a modern, extensible Python project manager. 
It creates a virtual environment for each project and manages dependencies.

> pip install hatch
 
### Running tests

> hatch test

or

> hatch run testing:cov

### Formatting code

> hatch run linting:format

### Checking types

> hatch run linting:typing

## Publish to PyPI

> hatch build
> hatch upload

If you want NULS2 support you will need to install nuls2-python
(currently only available on github):

> pip install aleph-sdk-python[nuls2]

To install from source and still be able to modify the source code:

> pip install -e .

