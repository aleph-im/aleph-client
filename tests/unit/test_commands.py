import subprocess
from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest
from aleph.sdk.chains.common import generate_key
from typer.testing import CliRunner

from aleph_client.__main__ import app
from typing import Generator

runner = CliRunner()


@pytest.fixture
def empty_account_file() -> Generator[Path, None, None]:
    with NamedTemporaryFile() as key_file:
        yield Path(key_file.name)


@pytest.fixture
def account_file(empty_account_file: Path) -> Path:
    private_key = generate_key()
    empty_account_file.write_bytes(private_key)
    return empty_account_file


def test_account_create(account_file: Path):
    old_key = account_file.read_bytes()
    result = runner.invoke(
        app, ["account", "create", "--replace", "--private-key-file", str(account_file)]
    )
    assert result.exit_code == 0, result.stdout
    new_key = account_file.read_bytes()
    assert new_key != old_key


def test_account_address(account_file: Path):
    result = runner.invoke(
        app, ["account", "address", "--private-key-file", str(account_file)]
    )
    assert result.exit_code == 0
    assert result.stdout.startswith("0x")
    assert len(result.stdout.strip()) == 42


def test_account_export_private_key(account_file: Path):
    result = runner.invoke(
        app, ["account", "export-private-key", "--private-key-file", str(account_file)]
    )
    assert result.exit_code == 0
    assert result.stdout.startswith("0x")
    assert len(result.stdout.strip()) == 66


def test_message_get():
    # Use subprocess to avoid border effects between tests caused by the initialisation
    # of the aiohttp client session out of an async context in the SDK. This avoids
    # a "no running event loop" error when running several tests back to back.
    result = subprocess.run(
        [
            "aleph",
            "message",
            "get",
            "bd79839bf96e595a06da5ac0b6ba51dea6f7e2591bb913deccded04d831d29f4",
        ],
        capture_output=True,
    )
    assert result.returncode == 0
    assert b"0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9" in result.stdout


def test_message_find():
    result = subprocess.run(
        [
            "aleph",
            "message",
            "find",
            "--pagination=1",
            "--page=1",
            "--start-date=1234",
            "--chains=ETH",
            "--hashes=bd79839bf96e595a06da5ac0b6ba51dea6f7e2591bb913deccded04d831d29f4",
        ],
        capture_output=True,
    )
    assert result.returncode == 0
    assert b"0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9" in result.stdout
    assert (
        b"bd79839bf96e595a06da5ac0b6ba51dea6f7e2591bb913deccded04d831d29f4"
        in result.stdout
    )


@pytest.mark.parametrize(
    "file_hash, content",
    [("QmeomffUNfmQy76CQGy9NdmqEnnHU9soCexBnGU3ezPHVH", "test\n")],
)
def test_file_download(file_hash, content):
    with NamedTemporaryFile() as temp_file:
        subprocess.run(
            ["aleph", "file", "download", file_hash, "--path", temp_file.name],
            check=True,
            timeout=30,
        )

        with open(temp_file.name) as file:
            content_file = file.read()

    assert content_file == content


@pytest.mark.parametrize(
    "file_hash, content",
    [("QmeomffUNfmQy76CQGy9NdmqEnnHU9soCexBnGU3ezPHVH", "test\n")],
)
def test_file_download_ipfs(file_hash, content):
    with NamedTemporaryFile() as temp_file:
        subprocess.run(
            [
                "aleph",
                "file",
                "download",
                file_hash,
                "--use-ipfs",
                "--path",
                temp_file.name,
            ],
            check=True,
            timeout=30,
        )

        with open(temp_file.name) as file:
            content_file = file.read()

    assert content_file == content
