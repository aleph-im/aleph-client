import json
import os
import pytest
from pathlib import Path

from aleph.sdk.chains.ethereum import ETHAccount
from typer.testing import CliRunner

from aleph_client.__main__ import app

runner = CliRunner()


def get_account(my_account_file: Path) -> ETHAccount:
    with open(my_account_file, "rb") as fd:
        private_key = fd.read()

    return ETHAccount(private_key=private_key)


def get_test_message(account: ETHAccount):
    return {
        "chain": "ETH",
        "sender": account.get_address(),
        "type": "AGGREGATE",
        "item_hash": "0x1234",
    }


@pytest.mark.skip(reason="Not implemented.")
def test_message_amend(account_file: Path):
    # private_key = None
    private_key_file = get_account(account_file)
    debug = "--no-debug"

    result = runner.invoke(
        app,
        [
            "message",
            "amend",
            "--private-key-file", private_key_file,
            debug
        ],
    )

    assert result.exit_code == 0


@pytest.mark.skip(reason="Not implemented.")
def test_message_find():
    pagination = 1
    page = 1
    message_types = None
    content_types = None
    content_keys = None
    refs = None
    addresses = None
    tags = None
    hashes = "bd79839bf96e595a06da5ac0b6ba51dea6f7e2591bb913deccded04d831d29f4"
    channels = None
    chains = "ETH"
    start_date = 1234
    end_date = None
    ignore_invalid_messages = "--no-ignore-invalid-messages"

    result = runner.invoke(
        app,
        [
            "message",
            "find",
            "--pagination", pagination,
            "--page", page,
            "--message-types", message_types,
            "--content-types", content_types,
            "--content-keys", content_keys,
            "--refs", refs,
            "--addresses", addresses,
            "--tags", tags,
            "--hashes", hashes,
            "--channels", channels,
            "--chains", chains,
            "--start-date", start_date,
            "--end-date", end_date,
            "--ignore-invalid-messages", ignore_invalid_messages
        ],
    )

    assert result.exit_code == 0

    assert "0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9" in result.stdout

    assert ("bd79839bf96e595a06da5ac0b6ba51dea6f7e2591bb913deccded04d831d29f4" in result.stdout)


@pytest.mark.skip(reason="Not implemented.")
def test_message_forget(account_file: Path):
    reason = None
    channel = None
    # private_key = None
    private_key_file = get_account(account_file)
    debug = "--no-debug"

    result = runner.invoke(
        app,
        [
            "message",
            "forget",
            "--reason", reason,
            "--channel", channel,
            "--private-key-file", private_key_file,
            debug,
        ],
    )

    assert result.exit_code == 0


def test_message_get():
    # Use subprocess to avoid border effects between tests caused by the initialisation
    # of the aiohttp client session out of an async context in the SDK. This avoids
    # a "no running event loop" error when running several tests back to back.

    item_hash = "bd79839bf96e595a06da5ac0b6ba51dea6f7e2591bb913deccded04d831d29f4"

    result = runner.invoke(
        app,
        [
            "message",
            "get",
            item_hash,
        ],
    )

    assert result.exit_code == 0

    assert "0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9" in result.stdout


def test_message_post(account_file):
    test_file_path = Path(os.path.join(
        Path(__file__).parent.parent.parent, "fixtures", "post.json")
    ).absolute().as_posix()

    path = str(test_file_path),
    message_type = "test"
    ref = None
    channel = None
    # private_key = None
    private_key_file = get_account(account_file)
    debug = "--no-debug"

    result = runner.invoke(
        app,
        [
            "message",
            "post",
            "--path", path,
            "--type", message_type,
            "--ref", ref,
            "--channel", channel,
            "--private-key-file", private_key_file,
            debug
        ],
    )

    assert result.exit_code == 0

    assert "item_hash" in result.stdout


def test_message_sign(account_file):
    # private_key = None
    private_key_file = get_account(account_file)
    message = get_test_message(private_key_file)
    debug = "--no-debug"

    result = runner.invoke(
        app,
        [
            "message",
            "sign",
            "--message", json.dumps(message),
            "--private-key-file", private_key_file,
            debug
        ],
    )

    assert result.exit_code == 0

    assert "signature" in result.stdout


def test_message_sign_stdin(account_file):
    # private_key = None
    private_key_file = get_account(account_file)
    message = get_test_message(private_key_file)
    debug = "--no-debug"

    result = runner.invoke(
        app,
        [
            "message",
            "sign",
            "--message", message,
            "--private-key-file", private_key_file,
            debug
        ],
        input=json.dumps(message),
    )

    assert result.exit_code == 0

    assert "signature" in result.stdout


def test_message_watch(account_file: Path):
    indent = None
    debug = "--no-debug"

    result = runner.invoke(
        app,
        [
            "message",
            "watch",
            "--indent", indent,
            debug
        ],
    )

    assert result.exit_code == 0
