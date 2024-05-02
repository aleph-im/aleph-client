import os
from pathlib import Path

from typer.testing import CliRunner

from aleph_client.__main__ import app

runner = CliRunner()


def test_file_upload(account_file: Path):
    path = (
        Path(
            os.path.join(
                Path(__file__).parent.parent.parent, "fixtures", "anything.txt"
            )
        )
        .absolute()
        .as_posix()
    )
    private_key_file = str(account_file)

    result = runner.invoke(
        app,
        [
            "file",
            "upload",
            path,
            "--private-key-file",
            str(private_key_file),
        ],
    )

    assert result.exit_code == 0
    assert result.stdout


def test_file_download():
    hash = "QmeomffUNfmQy76CQGy9NdmqEnnHU9soCexBnGU3ezPHVH"
    use_ipfs = "--no-use-ipfs"
    output_path = "."
    debug = "--no-debug"

    result = runner.invoke(
        app,
        [
            "file",
            "download",
            hash,
            use_ipfs,
            "--output-path",
            output_path,
            debug,
        ],  # 5 bytes file
    )

    assert result.exit_code == 0

    assert result.stdout is not None


def test_file_forget(account_file: Path):
    item_hash = "QmeomffUNfmQy76CQGy9NdmqEnnHU9soCexBnGU3ezPHVH"
    reason = "reason"
    channel = "TEST"
    private_key_file = str(account_file)
    debug = "--no-debug"

    result = runner.invoke(
        app,
        [
            "file",
            "forget",
            item_hash,
            reason,
            "--channel",
            channel,
            "--private-key-file",
            str(private_key_file),
            debug,
        ],
    )

    assert result.exit_code == 0

    assert result.stdout is not None


def test_file_list(account_file: Path):
    private_key_file = str(account_file)
    pagination = 100
    page = 1

    result = runner.invoke(
        app,
        [
            "file",
            "list",
            "--private-key-file",
            str(private_key_file),
            "--pagination",
            str(pagination),
            "--page",
            str(page),
        ],
    )

    assert result.exit_code == 0

    assert result.stdout is not None


def test_file_pin(account_file: Path):
    item_hash = "QmeomffUNfmQy76CQGy9NdmqEnnHU9soCexBnGU3ezPHVH"
    channel = "TEST"
    private_key_file = str(account_file)

    result = runner.invoke(
        app,
        [
            "file",
            "pin",
            item_hash,
            "--channel",
            channel,
            "--private-key-file",
            str(private_key_file),
        ],
    )

    assert result.exit_code == 0
