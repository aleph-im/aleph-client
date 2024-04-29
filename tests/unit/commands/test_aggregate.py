import asyncio
import json
import re
import textwrap
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aleph_client.__main__ import app

runner = CliRunner()


@pytest.fixture
def fixture_aggregate_post(account_file: Path):
    key = "key"
    content = """{"c": 3, "d": "test"}"""
    address = None
    channel = "TEST"
    inline = "--no-inline"
    sync = "--no-sync"
    private_key_file = str(account_file)
    debug = "--no-debug"

    result = runner.invoke(
        app,
        [
            "aggregate",
            "post",
            key,
            content,
            "--address",
            address,
            "--channel",
            channel,
            "--private-key-file",
            private_key_file,
            inline,
            sync,
            debug,
        ],
    )

    asyncio.run(asyncio.sleep(1))

    return result


def test_aggregate_post(fixture_aggregate_post):
    result = fixture_aggregate_post

    assert result.exit_code == 0, result.stdout

    pattern = textwrap.dedent(
        """\
        \\{
            "chain": "ETH",
            "sender": ".*",
            "type": "AGGREGATE",
            "channel": "TEST",
            "confirmations": null,
            "confirmed": null,
            "signature": ".*",
            "size": null,
            "time": [0-9]+\\.[0-9]+,
            "item_type": "storage",
            "item_content": null,
            "hash_type": null,
            "item_hash": ".*",
            "content": \\{
                "address": ".*",
                "time": [0-9]+\\.[0-9]+,
                "key": "key",
                "content": \\{
                    "c": 3,
                    "d": "test"
                \\}
            \\},
            "forgotten_by": null
        \\}
        """
    )

    assert re.fullmatch(pattern, result.stdout)


def test_aggregate_get(account_file: Path, fixture_aggregate_post):
    key = "key"
    address = None
    private_key_file = str(account_file)
    debug = "--no-debug"

    result = runner.invoke(
        app,
        [
            "aggregate",
            "get",
            key,
            "--address",
            address,
            "--private-key-file",
            private_key_file,
            debug,
        ],
    )

    assert result.exit_code == 0, result.stdout

    expected_content = """{"c": 3, "d": "test"}"""

    assert json.dumps(
        json.loads(expected_content), separators=(",", ":")
    ) == json.dumps(json.loads(result.stdout), separators=(",", ":"))


def test_aggregate_forget(account_file: Path, fixture_aggregate_post):
    hash = json.loads(fixture_aggregate_post.stdout)["item_hash"]

    key = hash
    channel = "TEST"
    private_key_file = str(account_file)
    reason = "Testing reasons."
    debug = "--debug"

    result = runner.invoke(
        app,
        [
            "aggregate",
            "forget",
            key,
            "--channel",
            channel,
            "--reason",
            reason,
            "--private-key-file",
            private_key_file,
            debug,
        ],
    )

    assert result.exit_code == 0, result.stdout

    pattern = r".*forgotten_by=.*, <MessageStatus.PENDING: 'pending'.*"
    assert re.match(pattern, result.stdout)
