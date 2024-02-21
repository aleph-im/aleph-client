import re
import tempfile
from pathlib import Path

from typer.testing import CliRunner

from aleph_client.__main__ import app
import pytest

runner = CliRunner()


@pytest.mark.skip(reason="Not implemented.")
def test_program_unpersist(account_file: Path):
    item_hash = "item_hash"
    private_key = None
    private_key_file = str(account_file)
    debug = "--debug" # [--debug|--no-debug]

    result = runner.invoke(
        app, [
            "program", "unpersist", item_hash,
            "--private-key-file", private_key_file,
            debug,
        ]
    )

    assert result.exit_code == 0
    assert result.stdout

@pytest.mark.skip(reason="Not implemented.")
def test_program_upload(account_file: Path):
    path = "path"
    entrypoint = "entrypoint"
    channel = "channel"
    memory = "memory"
    vcpus = "vcpus"
    timeout_seconds = "tomeout_seconds"
    private_key = None
    private_key_file = str(account_file)
    print_messages = "--print-messages" # [--print-message|--no-print-message]
    print_code_message = "--print-code-message" # [--print-code-message|--no-print-code-message]
    print_program_message = "--print-program-message" # [--print-program-message|--no-print-program-message]
    runtime = "runtime"
    beta = "--beta" # [--beta|--no-beta]
    debug = "--debug" # [--debug|--no-debug]
    persistent = "--persistent" # [--persistent|--no-persistent]
    persistent_volume = "persistent_volume"
    ephemeral_volume = "ephemeral_volume"
    immutable_volume = "immutable_volume"


    result = runner.invoke(
        app, [
            "program", "update", path, entrypoint,
            "--channel", channel,
            "--memory", memory,
            "--vcpus", vcpus,
            "--timeout-seconds", timeout_seconds,
            "--private-key-file", private_key_file,
            print_messages,
            print_code_message,
            print_program_message,
            "--runtime", runtime,
            beta,
            debug,
            persistent,
            "--persistent-volume", persistent_volume,
            "--ephemeral-volume", ephemeral_volume,
            "--immutable-volume", immutable_volume
        ]
    )

    assert result.exit_code == 0
    assert result.stdout

@pytest.mark.skip(reason="Not implemented.")
def test_program_update(account_file: Path):
    item_hash = "item_hash"
    path = "path"
    private_key = None
    private_key_file = str(account_file)
    print_message = "--print-message" # [--print-message|--no-print-message]
    debug = "--debug" # [--debug|--no-debug]

    result = runner.invoke(
        app, [
            "program", "update", item_hash, path,
            "--private-key-file", private_key_file,
            print_message,
            debug,
        ]
    )

    assert result.exit_code == 0
    assert result.stdout

def test_program_unpersist(account_file: Path):
    item_hash = "098f6bcd4621d373cade4e832627b4f6"

    result = runner.invoke(
        app, ["program", "unpersist", item_hash, "--private-key-file", str(account_file)]
    )

    assert result.exit_code == 0, result.stdout


def test_program_update(account_file: Path):
    item_hash = "098f6bcd4621d373cade4e832627b4f6"
    path = tempfile.TemporaryFile()

    result = runner.invoke(
        app, ["program", "update", item_hash, path, "--private-key-file", str(account_file)]
    )

    assert result.exit_code == 0, result.stdout


def test_program_upload(account_file: Path):
    path = tempfile.TemporaryFile()
    entrypoint = "entrypoint"
    channel = "channel"
    memory = ""


    result = runner.invoke(
        app, ["program", "upload", item_hash, path, "--private-key-file", str(account_file)]
    )

    assert result.exit_code == 0, result.stdout