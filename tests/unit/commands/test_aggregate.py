import re
import textwrap
from pathlib import Path
from typer.testing import CliRunner

from aleph_client.__main__ import app

runner = CliRunner()


def test_aggregate_post(account_file: Path):
    key = "key"
    content = """{"c": 3, "d": "test"}"""
    address = None
    channel = "channel"
    inline = "--no-inline"
    sync = "--no-sync"
    # private_key = None
    private_key_file = str(account_file)
    debug = "--no-debug"

    result = runner.invoke(
        app, [
            "aggregate", "post", key, content,
            "--address", address,
            "--channel", channel,
            "--private-key-file", private_key_file,
            inline,
            sync,
            debug
        ]
    )

    assert result.exit_code == 0, result.stdout

    pattern = textwrap.dedent(
        '''\
        \{
            "chain": "ETH",
            "sender": ".*",
            "type": "AGGREGATE",
            "channel": "channel",
            "confirmations": null,
            "confirmed": null,
            "signature": ".*",
            "size": null,
            "time": [0-9]+\.[0-9]+,
            "item_type": "storage",
            "item_content": null,
            "hash_type": null,
            "item_hash": ".*",
            "content": \{
                "address": ".*",
                "time": [0-9]+\.[0-9]+,
                "key": "key",
                "content": \{
                    "c": 3,
                    "d": "test"
                \}
            \},
            "forgotten_by": null
        \}
        '''
    )

    assert re.fullmatch(pattern, result.stdout)


# TODO Stopped here!!!
def test_aggregate_get(account_file: Path):
    key = "key"
    address = None
    # private_key = None
    private_key_file = str(account_file)
    debug = "--no-debug"

    result = runner.invoke(
        app, [
            "aggregate", "get", key,
            "--address", address,
            "--private-key-file", private_key_file,
            debug
        ]
    )

    print("exit_code:")
    print(result.exit_code)
    print("stdout:")

    assert result.exit_code == 0, result.stdout


def test_aggregate_forget(account_file: Path):
    key = None
    channel = None
    # private_key = None
    private_key_file = str(account_file)
    reason = None
    debug = "--no-debug"

    result = runner.invoke(
        app, [
            "aggregate", "forget", key,
            "--channel", channel,
            "--reason", reason,
            "--private-key-file", private_key_file,
            debug
        ]
    )

    assert result.exit_code == 0, result.stdout
