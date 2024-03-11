import re
import os
import tempfile
from pathlib import Path

from typer.testing import CliRunner

from aleph_client.__main__ import app
import pytest

runner = CliRunner()


def test_program_upload(account_file: Path):
    path = Path(os.path.join(
        Path(__file__).parent.parent.parent, "fixtures", "example_program_upload.zip")
    ).absolute().as_posix()

    entrypoint = "__init__:app"
    channel = "channel"
    memory = "memory"
    vcpus = "vcpus"
    timeout_seconds = "tomeout_seconds"
    private_key = None
    private_key_file = str(account_file)
    print_messages = "--print-messages" # [--print-message|--no-print-message]
    print_code_message = "--print-code-message" # [--print-code-message|--no-print-code-message]
    print_program_message = "--print-program-message" # [--print-program-message|--no-print-program-message]
    runtime = "f873715dc2feec3833074bd4b8745363a0e0093746b987b4c8191268883b2463"
    beta = "--beta" # [--beta|--no-beta]
    debug = "--debug" # [--debug|--no-debug]
    persistent = "--persistent" # [--persistent|--no-persistent]
    persistent_volume = "persistent_volume"
    ephemeral_volume = "ephemeral_volume"
    immutable_volume = "immutable_volume"


    result = runner.invoke(
        app, [
            "program", "upload", path, entrypoint,
            # "--channel", channel,
            # "--memory", memory,
            # "--vcpus", vcpus,
            # "--timeout-seconds", timeout_seconds,
            # "--private-key-file", private_key_file,
            # print_messages,
            # print_code_message,
            # print_program_message,
            "--runtime", runtime,
            # beta,
            # debug,
            # persistent,
            # "--persistent-volume", persistent_volume,
            # "--ephemeral-volume", ephemeral_volume,
            # "--immutable-volume", immutable_volume
        ]
    )

    pattern = r"Your program has been uploaded on aleph.im"
    assert re.match(pattern, result.stdout)


@pytest.fixture
def item_hash_upload(account_file: Path):
    path = Path(os.path.join(
        Path(__file__).parent.parent.parent, "fixtures", "example_program_upload.zip")
    ).absolute().as_posix()

    entrypoint = "__init__:app"
    runtime = "f873715dc2feec3833074bd4b8745363a0e0093746b987b4c8191268883b2463"

    result = runner.invoke(
        app, [
            "program", "upload", path, entrypoint, "--runtime", runtime
        ]
    )

    pattern = r'https://aleph\.sh/vm/(\w+)'
    matchings = re.findall(pattern, result.stdout)
    if matchings:
        item_hash = matchings[0]
        return item_hash


def test_program_update(account_file: Path, item_hash_upload):
    item_hash = item_hash_upload
    path = Path(os.path.join(
        Path(__file__).parent.parent.parent, "fixtures", "example_program_upload.zip")
    ).absolute().as_posix()
    private_key = None
    private_key_file = str(account_file)
    # print_message = "--print-message" # [--print-message|--no-print-message]
    # debug = "--debug" # [--debug|--no-debug]

    result = runner.invoke(
        app, [
            "program", "update", item_hash, path,
            "--private-key-file", private_key_file
            #print_message,
            #debug,
        ]
    )

    assert result.exit_code == 0
    assert result.stdout

def test_program_unpersist(account_file: Path, item_hash_upload):
    item_hash = item_hash_upload
    private_key = None
    private_key_file = str(account_file)
    # debug = "--debug" # [--debug|--no-debug]

    result = runner.invoke(
        app, [
            "program", "unpersist", item_hash,
            "--private-key-file", private_key_file,
            # debug,
        ]
    )

    assert result.exit_code == 0
    assert result.stdout

    print(result.stdout)