# -*- coding: utf-8 -*-
"""
    Dummy conftest.py for aleph_client.

    If you don't know what this is for, just leave it empty.
    Read more about conftest.py under:
    https://pytest.org/latest/plugins.html
"""
from os import mkdir
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import Generator

import pytest
from aleph.sdk.chains.common import generate_key
from aleph.sdk.conf import settings


@pytest.fixture
def new_config_home() -> Generator[Path, None, None]:
    with TemporaryDirectory() as temp_dir:
        settings.CONFIG_HOME = temp_dir
        mkdir(Path(settings.CONFIG_HOME) / "private-keys")
        yield Path(settings.CONFIG_HOME)


@pytest.fixture
def empty_account_file(new_config_home: Path) -> Generator[Path, None, None]:
    with NamedTemporaryFile(suffix=".key", dir=new_config_home / "private-keys") as key_file:
        yield Path(key_file.name)


@pytest.fixture
def account_file(empty_account_file: Path) -> Generator[Path, None, None]:
    with open(Path(settings.CONFIG_HOME) / "config.json", "w", encoding="utf-8") as config_file:
        config_file.write(f'{{"path": "{empty_account_file}", "chain": "ETH"}}')
    private_key = generate_key()
    empty_account_file.write_bytes(private_key)
    yield empty_account_file
