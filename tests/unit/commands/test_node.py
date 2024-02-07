import re

from typer.testing import CliRunner

from aleph_client.__main__ import app

runner = CliRunner()


def test_node_compute():
	json = "--no-json"
	active = "--no-active"
	address = None
	debug = "--no-debug"

	result = runner.invoke(
		app, [
			"node",
			"compute",
			json,
			active,
			"--address", address,
			debug
		]
	)

	assert result.exit_code == 0

	pattern = r".*Compute Node Information.*"
	assert re.match(pattern, result.stdout)
	# pattern = r".*?([0-9]+\.[0-9]+%|100\.00%|0\.00%).*?([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}).*?([0-9]+\.[0-9]+%|100\.00%).*?([a-z]+).*?"
	# assert len(re.findall(pattern, result.stdout, re.MULTILINE)) > 0


def test_node_core():
	json = "--no-json"
	active = "--no-active"
	address = None
	debug = "--no-debug"

	result = runner.invoke(
		app, [
			"node",
			"core",
			json,
			active,
			"--address", address,
			debug
		]
	)

	assert result.exit_code == 0
