from tempfile import NamedTemporaryFile

from typer.testing import CliRunner

from aleph_client.__main__ import app

runner = CliRunner()


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
