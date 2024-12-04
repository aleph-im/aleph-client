# -*- coding: utf-8 -*-
"""
    Dummy conftest.py for aleph_client.

    If you don't know what this is for, just leave it empty.
    Read more about conftest.py under:
    https://pytest.org/latest/plugins.html
"""
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Generator, Tuple

import pytest
from aleph.sdk.chains.common import generate_key


@pytest.fixture
def new_config_file() -> Generator[Path, None, None]:
    with NamedTemporaryFile(suffix=".json") as config_file:
        yield Path(config_file.name)


@pytest.fixture
def empty_account_file() -> Generator[Path, None, None]:
    with NamedTemporaryFile(suffix=".key") as key_file:
        yield Path(key_file.name)


@pytest.fixture
def env_files(new_config_file: Path, empty_account_file: Path) -> Generator[Tuple[Path, Path], None, None]:
    new_config_file.write_text(f'{{"path": "{empty_account_file}", "chain": "ETH"}}')
    empty_account_file.write_bytes(generate_key())
    yield empty_account_file, new_config_file
