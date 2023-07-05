from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest
from aleph.sdk.chains.common import generate_key
from typer.testing import CliRunner

from aleph_client.__main__ import app

runner = CliRunner()


@pytest.fixture
def empty_account_file() -> Path:
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
    result = runner.invoke(
        app,
        [
            "message",
            "get",
            "bd79839bf96e595a06da5ac0b6ba51dea6f7e2591bb913deccded04d831d29f4",
        ],
    )
    assert result.exit_code == 0
    assert "0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9" in result.stdout


def test_message_find():
    result = runner.invoke(
        app,
        [
            "message",
            "find",
            "--pagination=1",
            "--page=1",
            "--start-date=1234",
            "--chains=ETH",
            "--hashes=bd79839bf96e595a06da5ac0b6ba51dea6f7e2591bb913deccded04d831d29f4"
        ],
    )
    assert result.exit_code == 0
    assert "0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9" in result.stdout
    assert "bd79839bf96e595a06da5ac0b6ba51dea6f7e2591bb913deccded04d831d29f4" in result.stdout
