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


def test_sign_message():
    result = subprocess.run(
        [
            "aleph",
            "message",
            "sign",
            "--message",
            "{\"chain\":\"SupportedChains.Ethereum\",\"sender\":\"0x48A87924135892bEE2F264547a0D69909b3bA5C6\",\"type\":\"authorization_challenge\",\"item_hash\":\"d5b64a7c115e477a1e292e937143c1e7bfcf5442f43423f639eb8d9f57a91c76b776e90cc53ba1e7150a5d7521a428b721a101427e37f3d00a6c3cd124cf118b\"}",
        ],
        capture_output=True,
    )

    assert result.returncode == 0
    assert b"signature" in result.stdout


def test_sign_raw():
    result = subprocess.run(
        [
            "aleph",
            "account",
            "sign",
            "--message",
            "some message",
        ],
        capture_output=True,
    )

    assert result.returncode == 0
    assert b"0x" in result.stdout
