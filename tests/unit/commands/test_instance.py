from typer.testing import CliRunner
from aleph_client.__main__ import app
import re
import pytest

runner = CliRunner()
item_hash = None


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
