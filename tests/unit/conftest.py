# -*- coding: utf-8 -*-
"""
    Dummy conftest.py for aleph_client.

    If you don't know what this is for, just leave it empty.
    Read more about conftest.py under:
    https://pytest.org/latest/plugins.html
"""
from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest

from aleph_client.chains.common import get_fallback_private_key
import aleph_client.chains.ethereum as ethereum
import aleph_client.chains.sol as solana
import aleph_client.chains.tezos as tezos

@pytest.fixture
def fallback_private_key() -> bytes:
    with NamedTemporaryFile() as private_key_file:
        yield get_fallback_private_key(path=Path(private_key_file.name))


@pytest.fixture
def ethereum_account() -> ethereum.ETHAccount:
    with NamedTemporaryFile(delete=False) as private_key_file:
        private_key_file.close()
        yield ethereum.get_fallback_account(path=Path(private_key_file.name))


@pytest.fixture
def solana_account() -> solana.SOLAccount:
    with NamedTemporaryFile(delete=False) as private_key_file:
        private_key_file.close()
        yield solana.get_fallback_account(path=Path(private_key_file.name))


@pytest.fixture
def tezos_account() -> tezos.TezosAccount:
    with NamedTemporaryFile(delete=False) as private_key_file:
        private_key_file.close()
        yield tezos.get_fallback_account(path=Path(private_key_file.name))
