import textwrap

import re

from typer.testing import CliRunner

from aleph_client.__main__ import app

runner = CliRunner()


def test_node_compute():
    json = "--no-json"
    active = "--no-active"
    address = None
    debug = "--no-debug"

    result = runner.invoke(
        app, [
            "node",
            "compute",
            json,
            active,
            "--address", address,
            debug
        ]
    )

    assert result.exit_code == 0

    pattern = textwrap.dedent(
        '''\
        .*Compute Node Information.*
        .*
        .* Score ┃ Name                        ┃    Creation Time    ┃ Decentralization ┃  Status.*
        .*
        │ [0-9]+\.[0-9]+% │ .* │ [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} │ .*[0-9]+\.[0-9]+% │ .* │
        [\s\S]*
        '''
    )

    assert re.fullmatch(pattern, result.stdout)


# TODO Stopped here!!!
def test_node_core():
    json = "--no-json"
    active = "--no-active"
    address = None
    debug = "--no-debug"

    result = runner.invoke(
        app, [
            "node",
            "core",
            json,
            active,
            "--address", address,
            debug
        ]
    )

    assert result.exit_code == 0

    pattern = textwrap.dedent(
        '''\
        .*Core Channel Node Information.*
        .*
        .* Score ┃ Name                           ┃ Staked    ┃ Linked ┃    Creation Time    ┃  Status
        .*
        │ [0-9]+\.[0-9]+% │ .* │ .* │ [0-9]+ │ [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} │ .*  │
        [\s\S]*
        '''
    )

    assert re.fullmatch(pattern, result.stdout)
