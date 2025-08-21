from __future__ import annotations

from unittest.mock import patch

import pytest

from aleph_client.commands.pricing import GroupEntity, prices_for_service


@pytest.mark.parametrize(
    ids=list(GroupEntity),
    argnames="args",
    argvalues=list(GroupEntity),
)
@pytest.mark.asyncio
async def test_prices_for_service(mock_pricing_info_response, capsys, args):
    print()  # For better display when pytest -v -s

    @patch("aiohttp.ClientSession.get")
    async def run(mock_get):
        mock_get.return_value = mock_pricing_info_response
        await prices_for_service(service=args)

    await run()
    captured = capsys.readouterr()
    assert captured.out.startswith("\n╭─ Pricing:")
