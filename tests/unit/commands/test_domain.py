import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aleph_client.__main__ import app

runner = CliRunner()


@pytest.mark.skip(reason="Not implemented.")
def test_domain_add_ipfs(account_file: Path):
    fqdn = "aleph.im"
    private_key_file = str(account_file)
    target = "ipfs"  # {ipfs|program|instance}
    item_hash = "098f6bcd4621d373cade4e832627b4f6"

    result = runner.invoke(
        app,
        [
            "domain",
            "add",
            fqdn,
            "--private-key-file",
            str(private_key_file),
            "--target",
            target,
            "--item-hash",
            item_hash,
        ],
    )

    assert result.exit_code == 0
    assert result.stdout


# noinspection DuplicatedCode
@pytest.mark.skip(reason="Not implemented.")
def test_domain_add_program(account_file: Path):
    fqdn = "aleph.im"  # domain
    private_key_file = str(account_file)
    target = "program"  # {ipfs|program|instance}
    item_hash = "098f6bcd4621d373cade4e832627b4f6"

    result = runner.invoke(
        app,
        [
            "domain",
            "add",
            fqdn,
            "--private-key-file",
            str(private_key_file),
            "--target",
            target,
            "--item-hash",
            item_hash,
        ],
    )

    assert result.exit_code == 0
    assert result.stdout


# noinspection DuplicatedCode
@pytest.mark.skip(reason="Not implemented.")
def test_domain_add_instance(account_file: Path):
    fqdn = "aleph.im"  # domain
    # private_key = None
    private_key_file = str(account_file)
    target = "instance"  # {ipfs|program|instance}
    item_hash = "098f6bcd4621d373cade4e832627b4f6"

    result = runner.invoke(
        app,
        [
            "domain",
            "add",
            fqdn,
            "--private-key-file",
            str(private_key_file),
            "--target",
            target,
            "--item-hash",
            item_hash,
        ],
    )

    assert result.exit_code == 0
    assert result.stdout


@pytest.mark.skip(reason="Not implemented.")
def test_domain_attach(account_file: Path):
    fqdn = "aleph.im"  # domain
    # private_key = None
    private_key_file = str(account_file)
    item_hash = "098f6bcd4621d373cade4e832627b4f6"

    result = runner.invoke(
        app,
        [
            "domain",
            "attach",
            fqdn,
            "--private-key-file",
            str(private_key_file),
            "--item-hash",
            item_hash,
        ],
    )

    assert result.exit_code == 0, result.stdout

    pattern = rf".*Attach resource to: {fqdn}.*"

    assert re.match(pattern, result.stdout)


@pytest.mark.skip(reason="Not implemented.")
def test_domain_detach(account_file: Path):
    fqdn = "aleph.im"  # domain
    # private_key = None
    private_key_file = str(account_file)

    result = runner.invoke(
        app,
        [
            "domain",
            "detach",
            fqdn,
            "--private-key-file",
            str(private_key_file),
        ],
    )

    assert result.exit_code == 0, result.stdout

    pattern = rf".*Detach resource of: {fqdn}.*"

    assert re.match(pattern, result.stdout)


def test_domain_info(account_file: Path):
    fqdn = "aleph.im"  # domain
    # private_key = None
    private_key_file = str(account_file)

    result = runner.invoke(
        app,
        [
            "domain",
            "info",
            fqdn,
            "--private-key-file",
            str(private_key_file),
        ],
    )

    assert result.exit_code == 0, result.stdout

    pattern = rf".*Domain: {fqdn} not configured.*"

    assert re.match(pattern, result.stdout)
