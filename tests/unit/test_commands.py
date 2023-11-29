import json
from pathlib import Path
from tempfile import NamedTemporaryFile

from aleph.sdk.chains.ethereum import ETHAccount
from typer.testing import CliRunner

from aleph_client.__main__ import app

runner = CliRunner()


def get_account(my_account_file: Path) -> ETHAccount:
    with open(my_account_file, "rb") as fd:
        private_key = fd.read()
    return ETHAccount(private_key=private_key)


def get_test_message(account: ETHAccount):
    return {
        "chain": "ETH",
        "sender": account.get_address(),
        "type": "AGGREGATE",
        "item_hash": "0x1234",
    }


def test_account_create(account_file: Path):
    old_key = account_file.read_bytes()
    result = runner.invoke(
        app, ["account", "create", "--replace", "--private-key-file", str(account_file)]
    )
    assert result.exit_code == 0, result.stdout
    new_key = account_file.read_bytes()
    assert new_key != old_key


def test_account_address(account_file: Path):
    result = runner.invoke(
        app, ["account", "address", "--private-key-file", str(account_file)]
    )
    assert result.exit_code == 0
    assert result.stdout.startswith("0x")
    assert len(result.stdout.strip()) == 42


def test_account_export_private_key(account_file: Path):
    result = runner.invoke(
        app, ["account", "export-private-key", "--private-key-file", str(account_file)]
    )
    assert result.exit_code == 0
    assert result.stdout.startswith("0x")
    assert len(result.stdout.strip()) == 66


def test_account_path():
    result = runner.invoke(app, ["account", "path"])
    assert result.stdout.startswith("/")


def test_message_get():
    # Use subprocess to avoid border effects between tests caused by the initialisation
    # of the aiohttp client session out of an async context in the SDK. This avoids
    # a "no running event loop" error when running several tests back to back.
    result = runner.invoke(
        app,
        [
            "message",
            "get",
            "bd79839bf96e595a06da5ac0b6ba51dea6f7e2591bb913deccded04d831d29f4",
        ],
    )
    assert result.exit_code == 0
    assert "0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9" in result.stdout


def test_message_find():
    result = runner.invoke(
        app,
        [
            "message",
            "find",
            "--pagination=1",
            "--page=1",
            "--start-date=1234",
            "--chains=ETH",
            "--hashes=bd79839bf96e595a06da5ac0b6ba51dea6f7e2591bb913deccded04d831d29f4",
        ],
    )
    assert result.exit_code == 0
    assert "0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9" in result.stdout
    assert (
        "bd79839bf96e595a06da5ac0b6ba51dea6f7e2591bb913deccded04d831d29f4"
        in result.stdout
    )


def test_post_message(account_file):
    test_file_path = Path(__file__).parent.parent / "test_post.json"
    result = runner.invoke(
        app,
        [
            "message",
            "post",
            "--private-key-file",
            str(account_file),
            "--path",
            str(test_file_path),
        ],
    )
    assert result.exit_code == 0
    assert "item_hash" in result.stdout


def test_sign_message(account_file):
    account = get_account(account_file)
    message = get_test_message(account)
    result = runner.invoke(
        app,
        [
            "message",
            "sign",
            "--private-key-file",
            str(account_file),
            "--message",
            json.dumps(message),
        ],
    )

    assert result.exit_code == 0
    assert "signature" in result.stdout


def test_sign_message_stdin(account_file):
    account = get_account(account_file)
    message = get_test_message(account)
    result = runner.invoke(
        app,
        [
            "message",
            "sign",
            "--private-key-file",
            str(account_file),
        ],
        input=json.dumps(message),
    )

    assert result.exit_code == 0
    assert "signature" in result.stdout


def test_sign_raw():
    result = runner.invoke(
        app,
        [
            "account",
            "sign-bytes",
            "--message",
            "some message",
        ],
    )

    assert result.exit_code == 0
    assert "0x" in result.stdout


def test_sign_raw_stdin():
    message = "some message"
    result = runner.invoke(
        app,
        [
            "account",
            "sign-bytes",
        ],
        input=message,
    )

    assert result.exit_code == 0
    assert "0x" in result.stdout


def test_file_upload():
    # Test upload a file to aleph network by creating a file and upload it to an aleph node
    with NamedTemporaryFile() as temp_file:
        temp_file.write(b"Hello World \n")
        result = runner.invoke(
            app,
            ["file", "upload", temp_file.name],
        )
        assert result.exit_code == 0
        assert result.stdout is not None


def test_file_download():
    # Test download a file to aleph network
    result = runner.invoke(
        app,
        [
            "file",
            "download",
            "QmeomffUNfmQy76CQGy9NdmqEnnHU9soCexBnGU3ezPHVH",
        ],  # 5 bytes file
    )
    assert result.exit_code == 0
    assert result.stdout is not None
