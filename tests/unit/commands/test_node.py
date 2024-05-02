import json

from typer.testing import CliRunner

from aleph_client.__main__ import app

runner = CliRunner()


def test_node_compute():
    result = runner.invoke(
        app, ["node", "compute", "--json", "--no-active", "--no-debug"]
    )

    assert result.exit_code == 0
    output = json.loads(result.stdout)
    assert isinstance(output, list)
    assert len(output) > 0
    assert isinstance(output[0], dict)


def test_node_core():
    result = runner.invoke(app, ["node", "core", "--json", "--no-active", "--no-debug"])

    assert result.exit_code == 0
    output = json.loads(result.stdout)
    assert isinstance(output, list)
    assert len(output) > 0
    assert isinstance(output[0], dict)
