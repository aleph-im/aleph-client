from pathlib import Path

import pytest
from typer.testing import CliRunner

from aleph_client.__main__ import app

runner = CliRunner()


def test_account_address(account_file: Path):
    private_key = None
    private_key_file = str(account_file)

    result = runner.invoke(
        app, ["account", "address", "--private-key-file", private_key_file]
    )

    assert result.exit_code == 0

    assert result.stdout.startswith("0x")

    assert len(result.stdout.strip()) == 42


@pytest.mark.skip(reason="Not implemented. It's failing the retrieve the balance for the address.")
def test_account_balance(account_file: Path):
    private_key = None
    private_key_file = str(account_file)

    result = runner.invoke(
        app, ["account", "balance", "--private-key-file", private_key_file]
    )

    assert result.exit_code == 0


def test_account_create(account_file: Path):
    old_key = account_file.read_bytes()
    result = runner.invoke(
        app, ["account", "create", "--replace", "--private-key-file", str(account_file)]
    )

    assert result.exit_code == 0, result.stdout

    new_key = account_file.read_bytes()

    assert new_key != old_key


def test_account_export_private_key(account_file: Path):
    result = runner.invoke(
        app, ["account", "export-private-key", "--private-key-file", str(account_file)]
    )
    assert result.exit_code == 0

    assert result.stdout.startswith("0x")

    assert len(result.stdout.strip()) == 66


def test_account_path():
    result = runner.invoke(app, ["account", "path"])

    assert result.stdout.startswith("/")


def test_sign_raw():
    result = runner.invoke(
        app,
        [
            "account",
            "sign-bytes",
            "--message",
            "some message",
        ],
    )

    assert result.exit_code == 0

    assert "0x" in result.stdout


def test_sign_raw_stdin():
    message = "some message"
    result = runner.invoke(
        app,
        [
            "account",
            "sign-bytes",
        ],
        input=message,
    )

    assert result.exit_code == 0

    assert "0x" in result.stdout

