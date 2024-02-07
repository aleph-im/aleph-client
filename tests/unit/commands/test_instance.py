from typer.testing import CliRunner
from aleph_client.__main__ import app
import re
import pytest

runner = CliRunner()
item_hash = None

@pytest.mark.skip(reason="Not implemented.")
def test_instance_create(account_file: Path):
	channel = "channel"
	memory = "memory"
	vcpus = "vcpus"
	timeout_seconds = "timeout_seconds"
	private_key = None
	private_key_file = str(account_file)
	ssh_pubkey_file = "ssh_pubkey_file"
	print_messages = "--print-messages" #[--print-messages|--no-print-messages]
	rootfs = "rootfs"
	rootfs_name = "rootfs_name"
	rootfs_size = "rootfs_size"
	debug = "--debug" # [--debug|--no-debug]
	persistent_volume = "persistent_volume"
	ephemeral_volume = "ephemeral_volume"
	immutable_volume = "immutable_volume"

	result = runner.invoke(
		app, [
			"instance", "create",
			"--channel", channel,
			"--memory", memory,
			"--vcpus", vcpus,
			"--timeout-seconds", timeout_seconds,
			"--private-key-file", private_key_file,
			"--ssh-pubkey-file", ssh_pubkey_file,
			print_messages,
			"--rootfs", rootfs,
			"--rootfs-name", rootfs_name,
			"--rootfs-size", rootfs_size,
			debug,
			"--persistent-volume", persistent_volume,
			"--ephemeral-volume", ephemeral_volume,
			"--imutable-volume", immutable_volume
		]
	)

	assert result.exit_code == 0
	assert result.stdout

@pytest.mark.skip(reason="Not implemented.")
def test_instance_delete(account_file: Path):
	item_hash = "item_hash"
	reason = "reason"
	private_key = None
	private_key_file = str(account_file)
	print_messages = "--print-messages" #[--print-messages|--no-print-messages]
	debug = "--debug" # [--debug|--no-debug]

	result = runner.invoke(
		app, [
			"instance", "delete",
			item_hash,
			"--reason", reason,
			"--private-key-file", private_key_file,
			print_messages,
			debug,
		]
	)

	assert result.exit_code == 0
	assert result.stdout

@pytest.mark.skip(reason="Not implemented.")
def test_instance_list(account_file: Path):
	address = "address"
	private_key = None
	private_key_file = str(account_file)
	json = "--json" # [--json|--no-json]
	debug = "--debug" # [--debug|--no-debug]

	result = runner.invoke(
		app, [
			"instance", "list",
			"--address", address
			"--private-key-file", private_key_file,
			json,
			debug,
		]
	)

	assert result.exit_code == 0
	assert result.stdout

@pytest.mark.skip(reason="Not implemented.")
def test_instance_create():
	global item_hash

	rootfs = "Ubuntu 22"
	rootfs_name = "Ubuntu 22"
	vcpus = 1
	memory = 256
	rootfs_size = 2000

	result = runner.invoke(
		app, [
			"instance", "create",
			"--rootfs", rootfs,
			"--rootfs-name", rootfs_name,
			"--vcpus", vcpus,
			"--memory", memory,
			"--rootfs-size", rootfs_size
		]
	)

	assert result.exit_code == 0
	assert result.stdout

	item_hash_regex = r"\b0x[a-fA-F0-9]{40,42}\b"
	item_hashes = re.findall(item_hash_regex, result.stdout)

	item_hash = item_hashes[0] if item_hashes else None


@pytest.mark.skip(reason="Not implemented.")
def test_instance_delete():
	result = runner.invoke(
		app, [
			"instance", "create",
			"--item_hash", item_hash,
		]
	)

	assert result.exit_code == 0
	assert result.stdout


def test_instance_list():
	result = runner.invoke(
		app, ["instance", "list"]
	)

	assert result.exit_code == 0
	assert result.stdout
	assert "Item Hash   Vcpus   Memory   Disk size   IPv6 address" in result.stdout
