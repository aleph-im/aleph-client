import json
import os
from pathlib import Path

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
	test_file_path = Path(os.path.join(Path(__file__).parent.parent.parent, "fixtures", "post.json")).absolute().as_posix()
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