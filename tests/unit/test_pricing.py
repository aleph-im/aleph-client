from __future__ import annotations

from unittest.mock import patch

import pytest
import typer

from aleph_client.commands.pricing import (
    GroupEntity,
    Pricing,
    PricingEntity,
    prices_for_service,
)


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


def test_display_table_for_tier_id_int_conversion():
    """Test that tier_id is properly converted to int in tier_data dictionary"""
    # Create a mock pricing instance
    pricing = Pricing(
        data={
            "pricing": {
                "instance": {
                    "compute_unit": {"vcpus": 2, "memory_mib": 4096, "disk_mib": 20480},
                    "price": {
                        "compute_unit": {"holding": 1000, "payg": 0.05},
                        "storage": {"holding": 0.01, "payg": 0.001},
                    },
                    "tiers": [{"id": "tier-1", "compute_units": 1}, {"id": "tier-2", "compute_units": 2}],
                }
            }
        }
    )

    # Mock dependencies
    with (
        patch("aleph_client.commands.pricing.validated_prompt", return_value="1") as mock_prompt,
        patch("rich.console.Console.print"),
    ):

        # Call the method
        result = pricing.display_table_for(pricing_entity=PricingEntity.INSTANCE, selector=True, verbose=True)

        # Verify tier_id was converted to int
        assert isinstance(result.tier, int)
        assert result.tier == 1

        # Verify prompt was called with correct function that checks for int
        mock_prompt.assert_called_once()
        # Get the validation function passed to validated_prompt
        validation_func = mock_prompt.call_args[0][1]
        # Test that it accepts integer strings and converts them
        assert validation_func("1") is True
        assert validation_func("2") is True
        assert validation_func("3") is False  # Not in tier_data


def test_display_table_empty_tier_data():
    """Test handling of empty tier_data dictionary"""
    # Create a mock pricing instance with no valid tiers
    pricing = Pricing(
        data={
            "pricing": {
                "instance": {
                    "compute_unit": {"vcpus": 2, "memory_mib": 4096, "disk_mib": 20480},
                    "price": {
                        "compute_unit": {"holding": 1000, "payg": 0.05},
                        "storage": {"holding": 0.01, "payg": 0.001},
                    },
                    "tiers": [],  # Empty tiers list
                }
            }
        }
    )

    # Mock typer.echo and Exit
    with patch("typer.echo") as mock_echo, pytest.raises(typer.Exit):

        # Call the method
        pricing.display_table_for(pricing_entity=PricingEntity.INSTANCE, selector=True, verbose=True)

        # Verify error message was echoed
        mock_echo.assert_called_once_with("No valid tiers found for instance")
