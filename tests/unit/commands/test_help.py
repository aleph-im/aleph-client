from typer.testing import CliRunner

from aleph_client.__main__ import app

runner = CliRunner()


def test_root_help():
    result = runner.invoke(
        app, [
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout

    assert "Upload and update programs on aleph.im VM" in result.stdout


def test_about_help():
    result = runner.invoke(
        app, [
            "about",
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout

    assert "version" in result.stdout


def test_about_version_help():
    result = runner.invoke(
        app, [
            "about",
            "version"
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_account_help():
    result = runner.invoke(
        app, [
            "account",
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout

    assert "Sign a message using your private key." in result.stdout


def test_account_address_help():
    result = runner.invoke(
        app, [
            "account",
            "address"
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_account_balance_help():
    result = runner.invoke(
        app, [
            "account",
            "address"
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_account_balance_help():
    result = runner.invoke(
        app, [
            "account",
            "balance"
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_account_create_help():
    result = runner.invoke(
        app, [
            "account",
            "create"
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_account_export_private_key_help():
    result = runner.invoke(
        app, [
            "account",
            "export-private-key"
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_account_path_help():
    result = runner.invoke(
        app, [
            "account",
            "path"
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_account_sign_bytes():
    result = runner.invoke(
        app, [
            "account",
            "sign-bytes"
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_aggregate_help():
    result = runner.invoke(
        app, [
            "aggregate",
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout

    assert "Manage aggregate messages on aleph.im" in result.stdout


def test_aggregate_forget_help():
    result = runner.invoke(
        app, [
            "aggregate",
            "forget"
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_aggregate_get_help():
    result = runner.invoke(
        app, [
            "aggregate",
            "get"
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_aggregate_post_help():
    result = runner.invoke(
        app, [
            "aggregate",
            "post"
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_domain_help():
    result = runner.invoke(
        app, [
            "domain",
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout

    assert "Manage custom Domain (dns) on aleph.im" in result.stdout


def test_domain_add_help():
    result = runner.invoke(
        app, [
            "domain",
            "add"
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_domain_attach_help():
    result = runner.invoke(
        app, [
            "domain",
            "attach"
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_domain_detach_help():
    result = runner.invoke(
        app, [
            "domain",
            "detach"
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_domain_info_help():
    result = runner.invoke(
        app, [
            "domain",
            "info"
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_file_help():
    result = runner.invoke(
        app, [
            "file",
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout

    assert "File uploading and pinning on IPFS and aleph.im" in result.stdout


def test_file_download_help():
    result = runner.invoke(
        app, [
            "file",
            "download"
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_file_forget_help():
    result = runner.invoke(
        app, [
            "file",
            "forget"
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_file_list_help():
    result = runner.invoke(
        app, [
            "file",
            "list"
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_file_pin_help():
    result = runner.invoke(
        app, [
            "file",
            "pin"
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_file_upload_help():
    result = runner.invoke(
        app, [
            "file",
            "upload"
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_instance_help():
    result = runner.invoke(
        app, [
            "instance",
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout

    assert "Manage instances (VMs) on aleph.im network" in result.stdout


def test_instance_create_help():
    result = runner.invoke(
        app, [
            "instance",
            "create"
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_instance_delete_help():
    result = runner.invoke(
        app, [
            "instance",
            "delete"
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_instance_list_help():
    result = runner.invoke(
        app, [
            "instance",
            "list"
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_message_help():
    result = runner.invoke(
        app, [
            "message",
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout

    assert "Post, amend, watch and forget messages on aleph.im" in result.stdout


def test_message_amend_help():
    result = runner.invoke(
        app, [
            "message",
            "amend",
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_message_find_help():
    result = runner.invoke(
        app, [
            "message",
            "find",
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_message_find_help():
    result = runner.invoke(
        app, [
            "message",
            "find",
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_message_forget_help():
    result = runner.invoke(
        app, [
            "message",
            "forget",
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout


def test_node_help():
    result = runner.invoke(
        app, [
            "node",
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout

    assert "Get node info on aleph.im network" in result.stdout


def test_program_help():
    result = runner.invoke(
        app, [
            "program",
            "--help"
        ]
    )

    assert result.exit_code == 0, result.stdout

    assert "Upload and update programs on aleph.im VM" in result.stdout
