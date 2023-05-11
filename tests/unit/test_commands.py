import os
from tempfile import NamedTemporaryFile

import pytest
from aleph.sdk.conf import settings as sdk_settings
from typer.testing import CliRunner

from aleph_client.__main__ import app

runner = CliRunner()


@pytest.fixture
def test_account_file():
    original_value = sdk_settings.PRIVATE_KEY_FILE
    with NamedTemporaryFile() as test_file:
        sdk_settings.PRIVATE_KEY_FILE = test_file.name
        yield
    sdk_settings.PRIVATE_KEY_FILE = original_value


def test_account_create(test_account_file):
    os.environ["ALEPH_PRIVATE_KEY_FILE"] = sdk_settings.PRIVATE_KEY_FILE
    result = runner.invoke(app, ["account", "create", "--replace"])
    assert result.exit_code == 0


def test_account_address(test_account_file):
    result = runner.invoke(app, ["account", "address"])
    assert result.exit_code == 0
    assert result.stdout.startswith("0x")
    assert len(result.stdout.strip()) == 42


def test_account_export_private_key(test_account_file):
    result = runner.invoke(app, ["account", "export-private-key"])
    assert result.exit_code == 0
    assert result.stdout.startswith("0x")
    assert len(result.stdout.strip()) == 66


def test_message_get(test_account_file):
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


def test_message_find(test_account_file):
    result = runner.invoke(
        app,
        [
            "message",
            "find",
            "--pagination=1",
            "--page=1",
            "--start-date=1234",
            "--chains=ETH",
        ],
    )
    assert result.exit_code == 0
    assert "0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9" in result.stdout
