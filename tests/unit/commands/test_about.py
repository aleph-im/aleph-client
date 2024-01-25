import re

from typer.testing import CliRunner

from aleph_client.__main__ import app

runner = CliRunner()


def test_about_help():
    result = runner.invoke(
        app, ["about", "--help"]
    )

    assert result.exit_code == 0, result.stdout

    assert "version" in result.stdout


def test_about_version():
    result = runner.invoke(
        app, ["about", "version"]
    )

    assert result.exit_code == 1, result.stdout

    pattern = r"Aleph CLI Version: \d+\.\d+\.\d+.*"

    assert re.match(pattern, result.stdout)
