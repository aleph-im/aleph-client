from typer.testing import CliRunner

from aleph_client.__main__ import app

runner = CliRunner()


def test_root_help():
    result = runner.invoke(
        app, ["--help"]
    )

    assert result.exit_code == 0, result.stdout

    assert "Upload and update programs on aleph.im VM" in result.stdout


def test_about_help():
    result = runner.invoke(
        app, ["about", "--help"]
    )

    assert result.exit_code == 0, result.stdout

    assert "version" in result.stdout


def test_account_help():
    result = runner.invoke(
        app, ["account", "--help"]
    )

    assert result.exit_code == 0, result.stdout

    assert "Sign a message using your private key." in result.stdout


def test_aggregate_help():
    result = runner.invoke(
        app, ["aggregate", "--help"]
    )

    assert result.exit_code == 0, result.stdout

    assert "Manage aggregate messages on aleph.im" in result.stdout


def test_domain_help():
    result = runner.invoke(
        app, ["domain", "--help"]
    )

    assert result.exit_code == 0, result.stdout

    assert "Manage custom Domain (dns) on aleph.im" in result.stdout


def test_file_help():
    result = runner.invoke(
        app, ["file", "--help"]
    )

    assert result.exit_code == 0, result.stdout

    assert "File uploading and pinning on IPFS and aleph.im" in result.stdout


def test_instance_help():
    result = runner.invoke(
        app, ["instance", "--help"]
    )

    assert result.exit_code == 0, result.stdout

    assert "Manage instances (VMs) on aleph.im network" in result.stdout


def test_message_help():
    result = runner.invoke(
        app, ["message", "--help"]
    )

    assert result.exit_code == 0, result.stdout

    assert "Post, amend, watch and forget messages on aleph.im" in result.stdout


def test_node_help():
    result = runner.invoke(
        app, ["node", "--help"]
    )

    assert result.exit_code == 0, result.stdout

    assert "Get node info on aleph.im network" in result.stdout


def test_program_help():
    result = runner.invoke(
        app, ["program", "--help"]
    )

    assert result.exit_code == 0, result.stdout

    assert "Upload and update programs on aleph.im VM" in result.stdout
