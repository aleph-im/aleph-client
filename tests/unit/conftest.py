# -*- coding: utf-8 -*-
"""
    Dummy conftest.py for aleph_client.

    If you don't know what this is for, just leave it empty.
    Read more about conftest.py under:
    https://pytest.org/latest/plugins.html
"""
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Generator

import pytest
from aleph.sdk.chains.common import generate_key


@pytest.fixture
def empty_account_file() -> Generator[Path, None, None]:
    with NamedTemporaryFile() as key_file:
        yield Path(key_file.name)


@pytest.fixture
def account_file(empty_account_file: Path) -> Path:
    private_key = generate_key()
    empty_account_file.write_bytes(private_key)
    return empty_account_file
