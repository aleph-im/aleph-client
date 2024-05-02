import os
from pathlib import Path
from typing import Dict

from typer.testing import CliRunner

from aleph_client.__main__ import app
from aleph_client.exit_codes import EX_NOFUNDS

runner = CliRunner()
item_hash = None


def test_instance_create(account_file: Path, ssh_keys_files: Dict[str, Path]):
    channel = "TEST"
    memory = 256
    vcpus = 1
    timeout_seconds = 30.0
    private_key_file = str(account_file)
    ssh_pubkey_file = str(ssh_keys_files["public_key"])
    print_messages = "--no-print-messages"
    rootfs = "Ubuntu 22"
    rootfs_size = 2000

    result = runner.invoke(
        app,
        [
            "instance",
            "create",
            "--channel",
            channel,
            "--memory",
            str(memory),
            "--vcpus",
            str(vcpus),
            "--timeout-seconds",
            str(timeout_seconds),
            "--private-key-file",
            private_key_file,
            "--ssh-pubkey-file",
            ssh_pubkey_file,
            print_messages,
            "--rootfs",
            rootfs,
            "--rootfs-size",
            str(rootfs_size),
            "--debug",
        ],
    )

    assert result.exit_code == EX_NOFUNDS


def test_instance_delete(account_file: Path):
    item_hash = "93eea5a38043f1eabd268704cccc1133394fda02cfdb8bc0a82a50e5e6eb41aa"  # some super old instance hash

    result = runner.invoke(
        app,
        [
            "instance",
            "delete",
            item_hash,
        ],
    )

    assert result.exit_code == os.EX_NOPERM


def test_instance_list(account_file: Path):
    address = "address"
    private_key_file = str(account_file)
    json = "--json"  # [--json|--no-json]
    debug = "--debug"  # [--debug|--no-debug]

    result = runner.invoke(
        app,
        [
            "instance",
            "list",
            "--address",
            address,
            "--private-key-file",
            str(private_key_file),
            json,
            debug,
        ],
    )

    assert result.exit_code == 0
    assert result.stdout
