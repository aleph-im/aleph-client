from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aleph.sdk.client.services.pricing import PricingEntity, PricingModel
from rich.console import Console

from aleph_client.commands.pricing import (
    GroupEntity,
    Pricing,
    fetch_pricing_aggregate,
    prices_for_service,
)


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


@pytest.mark.parametrize(
    ids=["instance", "instance_conf", "program", "program_persistent"],
    argnames="entity",
    argvalues=[
        PricingEntity.INSTANCE,
        PricingEntity.INSTANCE_CONFIDENTIAL,
        PricingEntity.PROGRAM,
        PricingEntity.PROGRAM_PERSISTENT,
    ],
)
def test_pricing_display_table_for_compute(entity, mock_pricing_info_response):
    """Test the display_table_for method for compute entities."""
    # Load pricing data from mock response
    pricing_data = mock_pricing_info_response.json.return_value["data"]["pricing"]

    pricing_model = PricingModel.model_validate(pricing_data)

    pricing = Pricing(pricing_model)
    pricing.console = MagicMock(spec=Console)

    pricing.display_table_for(entity)

    assert pricing.console.print.called

    pricing.display_table_for(entity, tier=1)

    assert pricing.console.print.call_count == 2


def test_pricing_display_table_for_storage(mock_pricing_info_response):
    """Test the display_table_for method for storage and web3 hosting."""
    # Load pricing data from mock response
    pricing_data = mock_pricing_info_response.json.return_value["data"]["pricing"]

    pricing_model = PricingModel.model_validate(pricing_data)

    pricing = Pricing(pricing_model)
    pricing.console = MagicMock(spec=Console)

    pricing.display_table_for(PricingEntity.STORAGE)

    assert pricing.console.print.called

    pricing.display_table_for(PricingEntity.WEB3_HOSTING)

    assert pricing.console.print.call_count == 2


@pytest.mark.asyncio
@patch("aleph_client.commands.instance.network.call_program_crn_list")
async def test_pricing_display_gpu_info(mock_call_program_crn_list, mock_pricing_info_response, mock_crn_list_obj):
    """Test the display_table_for method with GPU information."""
    # Setup mock for call_program_crn_list
    mock_call_program_crn_list.return_value = mock_crn_list_obj

    # Load pricing data from mock response
    pricing_data = mock_pricing_info_response.json.return_value["data"]["pricing"]

    pricing_model = PricingModel.model_validate(pricing_data)

    pricing = Pricing(pricing_model)
    pricing.console = MagicMock(spec=Console)

    network_gpu = mock_crn_list_obj.find_gpu_on_network()

    pricing.display_table_for(PricingEntity.INSTANCE_GPU_STANDARD, network_gpu=network_gpu)

    pricing.display_table_for(PricingEntity.INSTANCE_GPU_PREMIUM, network_gpu=network_gpu)

    assert pricing.console.print.call_count == 2


@pytest.mark.asyncio
async def test_fetch_pricing_aggregate(mock_pricing_info_response):
    """Test the fetch_pricing_aggregate function."""
    # Load pricing data from mock response
    pricing_data = mock_pricing_info_response.json.return_value["data"]["pricing"]

    pricing_model = PricingModel.model_validate(pricing_data)

    @patch("aleph_client.commands.pricing.AlephHttpClient")
    async def run(mock_client_class):
        # Setup the mock client
        mock_client = MagicMock()
        mock_client.__aenter__ = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__ = AsyncMock()

        mock_client.pricing = MagicMock()
        mock_client.pricing.get_pricing_aggregate = AsyncMock(return_value=pricing_model)

        mock_client_class.return_value = mock_client

        # Clear the cache
        fetch_pricing_aggregate.cache_clear()

        result = await fetch_pricing_aggregate()

        assert isinstance(result, Pricing)
        assert result.data == pricing_model

        # Call again to test caching
        await fetch_pricing_aggregate()

        assert mock_client.pricing.get_pricing_aggregate.call_count == 2

    await run()
