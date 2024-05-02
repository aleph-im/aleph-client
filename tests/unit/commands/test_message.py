import json
import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Union

import pytest
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


def create_test_message(private_key_file: Union[Path, str]):
    path = (
        Path(os.path.join(Path(__file__).parent.parent.parent, "fixtures", "post.json"))
        .absolute()
        .as_posix()
    )
    message_type = "POST"
    channel = "TEST"
    result = runner.invoke(
        app,
        [
            "message",
            "post",
            "--path",
            path,
            "--type",
            message_type,
            "--channel",
            channel,
            "--private-key-file",
            str(private_key_file),
        ],
    )
    time.sleep(1)
    return result


def test_message_post(account_file):
    result = create_test_message(account_file)

    assert result.exit_code == 0
    assert result.stdout


def test_message_amend(account_file: Path):
    result = create_test_message(account_file)
    message = json.loads(result.stdout)

    result = runner.invoke(
        app,
        ["message", "amend", message["item_hash"], "--content", '{"content": {"hello": "my bro"}}', "--private-key-file", str(account_file)],
    )
    assert result.exit_code == 0
    print(result.stdout)
    assert json.loads(result.stdout)["content"]["content"]["hello"] == "my bro"


def test_message_forget(account_file: Path):
    result = json.loads(create_test_message(account_file).stdout)

    result = runner.invoke(
        app,
        [
            "message",
            "forget",
            result["item_hash"],
            "--private-key-file",
            str(account_file),
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


def test_message_find():
    pagination = 1
    page = 1
    hashes = "bd79839bf96e595a06da5ac0b6ba51dea6f7e2591bb913deccded04d831d29f4"
    chains = "ETH"
    start_date = 1234
    ignore_invalid_messages = "--no-ignore-invalid-messages"

    result = runner.invoke(
        app,
        [
            "message",
            "find",
            "--pagination",
            str(pagination),
            "--page",
            str(page),
            "--hashes",
            hashes,
            "--chains",
            chains,
            "--start-date",
            str(start_date),
            "--ignore-invalid-messages",
            ignore_invalid_messages,
        ],
    )

    assert result.exit_code == 0

    assert "0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9" in result.stdout

    assert (
        "bd79839bf96e595a06da5ac0b6ba51dea6f7e2591bb913deccded04d831d29f4"
        in result.stdout
    )


def test_message_sign(account_file):
    private_key_file = account_file
    message = json.dumps(get_test_message(get_account(private_key_file)))

    result = runner.invoke(
        app,
        [
            "message",
            "sign",
            "--message",
            message,
            "--private-key-file",
            str(private_key_file),
        ],
    )

    assert result.exit_code == 0

    assert "signature" in result.stdout


def test_message_sign_stdin(account_file):
    private_key_file = account_file
    message = get_test_message(get_account(private_key_file))

    result = runner.invoke(
        app,
        [
            "message",
            "sign",
            "--private-key-file",
            str(private_key_file),
        ],
        input=json.dumps(message),
    )

    assert result.exit_code == 0

    assert "signature" in result.stdout


def test_message_watch(account_file: Path):
    debug = "--debug"
    message_ref = "bd79839bf96e595a06da5ac0b6ba51dea6f7e2591bb913deccded04d831d29f4"

    # runs indefinitely, we should just check if stdout prints something after some time and then kill the process
    proc = subprocess.Popen(["aleph", "message", "watch", message_ref, debug])
    time.sleep(1)
    proc.send_signal(signal.SIGINT)
    # Wait for the process to complete
    proc.wait()

    assert proc.returncode in [130, -2]  # 130 is the return code for SIGINT on most systems, -2 is the return code for SIGINT on Windows
