from pathlib import Path
from tempfile import NamedTemporaryFile

from typer.testing import CliRunner

from aleph_client.__main__ import app

runner = CliRunner()


def test_file_upload(account_file: Path):
    path = None
    channel = None
    private_key = None
    private_key_file = str(account_file)
    ref = None
    debug = "--no-debug"

    # Test upload a file to aleph network by creating a file and upload it to an aleph node
    with NamedTemporaryFile() as temp_file:
        temp_file.write(b"Hello World \n")

        path = temp_file.name

        result = runner.invoke(
            app,
            [
                "file",
                "upload",
                path,
                "--channel", channel,
                "--private-key-file", private_key_file,
                ref,
                debug
            ],
        )

        assert result.exit_code == 0

        assert result.stdout is not None


def test_file_download():
    hash = "QmeomffUNfmQy76CQGy9NdmqEnnHU9soCexBnGU3ezPHVH"
    use_ipfs = "--no-use-ipfs"
    output_path = "."
    file_name = None
    file_extension = None
    debug = "--no-debug"

    # Test download a file to aleph network
    result = runner.invoke(
        app,
        [
            "file",
            "download",
            hash,
            use_ipfs,
            "--output-path", output_path,
            "--file-name", file_name,
            "--file-extension", file_extension,
            debug
        ],  # 5 bytes file
    )

    assert result.exit_code == 0

    assert result.stdout is not None
