from typer.testing import CliRunner

from aleph_client.__main__ import app

runner = CliRunner()


def test_root_help():
    result = runner.invoke(
        app, ["--help"]
    )

    assert result.exit_code == 0, result.stdout

    assert "Upload and update programs on aleph.im VM" in result.stdout
