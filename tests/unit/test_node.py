from __future__ import annotations

import pytest

from aleph_client.commands.node import compute, core


@pytest.mark.asyncio
async def test_node_core(capsys):
    await core(
        json=False,
        active=True,
        address=None,
        ccn_hash=None,
        debug=False,
    )
    captured = capsys.readouterr()
    assert "Core Channel Node Information" in captured.out


@pytest.mark.asyncio
async def test_node_compute(capsys):
    await compute(
        json=False,
        active=True,
        address=None,
        payg_receiver=None,
        crn_url=None,
        crn_hash=None,
        ccn_hash=None,
        debug=False,
    )
    captured = capsys.readouterr()
    assert "Compute Node Information" in captured.out
