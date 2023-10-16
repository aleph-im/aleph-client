import subprocess
from pathlib import Path

from typer.testing import CliRunner

from aleph_client.__main__ import app

runner = CliRunner()


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


def test_file_list():
    result = subprocess.run(
        ["aleph", "file", "list", "0xd463495a6FEaC9921FD0C3a595B81E7B2C02B57d"],
        capture_output=True,
    )
    assert result.returncode == 0
    assert b"0xd463495a6FEaC9921FD0C3a595B81E7B2C02B57d" in result.stdout
