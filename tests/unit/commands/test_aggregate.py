from pathlib import Path

import pytest
from typer.testing import CliRunner

from aleph_client.__main__ import app

runner = CliRunner()


@pytest.mark.skip(reason="Not implemented.")
def test_aggregate_forget(account_file: Path):
    key = "key"
    channel = "channel"

    result = runner.invoke(
        app, ["aggregate", "forget", key, "--channel", channel, "--private-key-file", str(account_file)]
    )

    assert result.exit_code == 0, result.stdout


@pytest.mark.skip(reason="Not implemented.")
def test_aggregate_get(account_file: Path):
    key = "key"
    address = "address"

    result = runner.invoke(
        app, ["aggregate", "get", key, "--address", address, "--private-key-file", str(account_file)]
    )

    assert result.exit_code == 0, result.stdout


@pytest.mark.skip(reason="Not implemented.")
def test_aggregate_post(account_file: Path):
    key = "key"
    content = "{'c': 3, 'd': 4}"
    address = "address"
    channel = "channel"
    inline = "no-inline"
    sync = "no-sync"
    debug = "no-debug"

    result = runner.invoke(
        app, ["aggregate", "post", key, content, "--address", address, "--channel", channel, "--inline", inline, "--sync", sync, "--private-key-file", str(account_file), '--debug', debug]
    )

    assert result.exit_code == 0, result.stdout
