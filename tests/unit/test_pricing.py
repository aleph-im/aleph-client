from __future__ import annotations

import pytest

from aleph_client.commands.pricing import GroupEntity, prices_for_service


@pytest.mark.parametrize(
    ids=list(GroupEntity),
    argnames="args",
    argvalues=list(GroupEntity),
)
@pytest.mark.asyncio
async def test_prices_for_service(capsys, args):
    print()  # For better display when pytest -v -s
    await prices_for_service(service=args)
    captured = capsys.readouterr()
    assert captured.out.startswith("\n╭─ Pricing:")
