import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aleph_client.__main__ import app

runner = CliRunner()


@pytest.mark.skip(reason="Not implemented.")
def test_domain_add_ipfs(account_file: Path):
    domain = "aleph.im"
    item_hash = "098f6bcd4621d373cade4e832627b4f6"
    
    result = runner.invoke(
        app, ["domain", "add",  domain, "--private-key-file", str(account_file), "--target", "ipfs", "--item-hash", item_hash]
    )

    assert result.exit_code == 0, result.stdout


@pytest.mark.skip(reason="Not implemented.")
def test_domain_add_program(account_file: Path):
    domain = "aleph.im"
    item_hash = "098f6bcd4621d373cade4e832627b4f6"
    
    result = runner.invoke(
        app, ["domain", "add",  domain, "--private-key-file", str(account_file), "--target", "program", "--item-hash", item_hash]
    )

    assert result.exit_code == 0, result.stdout


@pytest.mark.skip(reason="Not implemented.")
def test_domain_add_instance(account_file: Path):
    domain = "aleph.im"
    item_hash = "098f6bcd4621d373cade4e832627b4f6"
    
    result = runner.invoke(
        app, ["domain", "add",  domain, "--private-key-file", str(account_file), "--target", "instance", "--item-hash", item_hash]
    )

    assert result.exit_code == 0, result.stdout


def test_domain_attach(account_file: Path):
    domain = "aleph.im"
    item_hash = "098f6bcd4621d373cade4e832627b4f6"

    result = runner.invoke(
        app, ["domain", "attach", domain, "--private-key-file", str(account_file), "--item-hash", item_hash]
    )

    assert result.exit_code == 0, result.stdout

    pattern = rf".*Attach resource to: {domain}.*"

    assert re.match(pattern, result.stdout)


def test_domain_detach(account_file: Path):
    domain = "aleph.im"

    result = runner.invoke(
        app, ["domain", "detach", domain, "--private-key-file", str(account_file)]
    )

    assert result.exit_code == 0, result.stdout

    pattern = rf".*Detach resource of: {domain}.*"

    assert re.match(pattern, result.stdout)


def test_domain_info(account_file: Path):
    domain = "aleph.im"

    result = runner.invoke(
        app, ["domain", "info", domain, "--private-key-file", str(account_file)]
    )

    assert result.exit_code == 0, result.stdout

    pattern = rf".*Domain: {domain} not configured.*"

    assert re.match(pattern, result.stdout)
