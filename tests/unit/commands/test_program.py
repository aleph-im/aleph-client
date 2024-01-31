import re
import tempfile
from pathlib import Path

from typer.testing import CliRunner

from aleph_client.__main__ import app

runner = CliRunner()


def test_program_unpersist(account_file: Path):
    item_hash = "098f6bcd4621d373cade4e832627b4f6"

    result = runner.invoke(
        app, ["program", "unpersist", item_hash, "--private-key-file", str(account_file)]
    )

    assert result.exit_code == 0, result.stdout


def test_program_update(account_file: Path):
    item_hash = "098f6bcd4621d373cade4e832627b4f6"
    path = tempfile.TemporaryFile()

    result = runner.invoke(
        app, ["program", "update", item_hash, path, "--private-key-file", str(account_file)]
    )

    assert result.exit_code == 0, result.stdout


def test_program_upload(account_file: Path):
    path = tempfile.TemporaryFile()
    entrypoint = "entrypoint"
    channel = "channel"
    memory = ""


    result = runner.invoke(
        app, ["program", "upload", item_hash, path, "--private-key-file", str(account_file)]
    )

    assert result.exit_code == 0, result.stdout