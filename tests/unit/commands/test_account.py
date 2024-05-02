import re
from pathlib import Path

from typer.testing import CliRunner

from aleph_client.__main__ import app

runner = CliRunner()


def test_account_address(account_file: Path):
    # private_key = None
    private_key_file = str(account_file)

    result = runner.invoke(
        app, ["account", "address", "--private-key-file", private_key_file]
    )

    assert result.exit_code == 0

    pattern = r"0x.*"
    assert re.match(pattern, result.stdout)

    assert len(result.stdout.strip()) == 42


# TODO Verify if the output message ""Failed to retrieve balance..." is ok!!!
def test_account_balance(account_file: Path):
    result = runner.invoke(
        app,
        [
            "account",
            "balance",
            "--private-key-file",
            str(account_file),
        ],
    )

    pattern = r"Failed to retrieve balance for address 0x.*\. Status code: 404"
    assert re.match(pattern, result.stdout)

    assert result.exit_code == 0


def test_account_create(account_file: Path):
    # private_key = None
    private_key_file = str(account_file)
    replace = "--replace"
    debug = "--no-debug"

    old_key = account_file.read_bytes()

    result = runner.invoke(
        app,
        ["account", "create", "--private-key-file", str(private_key_file), replace, debug],
    )

    assert result.exit_code == 0, result.stdout

    new_key = account_file.read_bytes()

    pattern = r"Private key stored in .*"
    assert re.match(pattern, result.stdout)

    assert new_key != old_key


def test_account_export_private_key(account_file: Path):
    # private_key = None
    private_key_file = str(account_file)

    result = runner.invoke(
        app, ["account", "export-private-key", "--private-key-file", private_key_file]
    )
    assert result.exit_code == 0

    assert result.stdout.startswith("0x")

    pattern = r"0x.*"
    assert re.match(pattern, result.stdout)

    assert len(result.stdout.strip()) == 66


def test_sign_bytes_raw(account_file: Path):
    message = "some message"
    # private_key = None
    private_key_file = str(account_file)
    debug = "--no-debug"

    result = runner.invoke(
        app,
        [
            "account",
            "sign-bytes",
            "--message",
            message,
            "--private-key-file",
            str(private_key_file),
            debug,
        ],
    )

    assert result.exit_code == 0

    pattern = r"0x.*"
    assert re.match(pattern, result.stdout)


def test_sign_bytes_raw_stdin(account_file: Path):
    message = "some message"
    # private_key = None
    private_key_file = str(account_file)
    debug = "--no-debug"

    result = runner.invoke(
        app,
        ["account", "sign-bytes", "--private-key-file", str(private_key_file), debug],
        input=message,
    )

    assert result.exit_code == 0

    pattern = r"0x.*"
    assert re.match(pattern, result.stdout)
