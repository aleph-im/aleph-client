from __future__ import annotations

import logging
from decimal import Decimal
from typing import Annotated, Optional

import typer
from aleph.sdk import AlephHttpClient
from aleph.sdk.client.services.crn import NetworkGPUS
from aleph.sdk.client.services.pricing import (
    PAYG_GROUP,
    PRICING_GROUPS,
    GroupEntity,
    Price,
    PricingEntity,
    PricingModel,
    PricingPerEntity,
    Tier,
)
from aleph.sdk.conf import settings
from aleph.sdk.utils import displayable_amount
from pydantic import BaseModel
from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from aleph_client.commands.utils import colorful_json, setup_logging
from aleph_client.utils import async_lru_cache, sanitize_url

logger = logging.getLogger(__name__)

pricing_link = (
    f"{sanitize_url(settings.API_HOST)}/api/v0/aggregates/0xFba561a84A537fCaa567bb7A2257e7142701ae2A.json?keys=pricing"
)


class SelectedTierPrice(BaseModel):
    hold: Decimal
    payg: Decimal  # Token by second
    storage: Optional[SelectedTierPrice] = None


class SelectedTier(BaseModel):
    tier: int
    compute_units: int
    vcpus: int
    memory: int
    disk: int
    gpu_model: Optional[str]
    price: SelectedTierPrice


class Pricing:
    def __init__(self, pricing_aggregate: PricingModel):
        self.data = pricing_aggregate
        self.console = Console()

    def _format_name(self, entity: PricingEntity):
        return entity.value.replace("_", " ").title()

    def _format_tier_id(self, name: str):
        return name.split("-", 1)[1]

    def _tier_matches(self, tier: Tier, only_tier: Optional[int]) -> bool:
        if only_tier is None:
            return True
        try:
            short_id = int(self._format_tier_id(tier.id))
        except ValueError:
            return False
        return short_id == only_tier

    def _process_network_gpu_info(self, tier: Tier, network_gpu: NetworkGPUS):
        available_gpu: dict[str, int] = {}
        for crn_url, gpus in network_gpu.available_gpu_list.items():
            for gpu in gpus:
                if gpu.model == tier.model:
                    # On this dict we want only count if there is a GPU for simplify draw
                    if not available_gpu.get(crn_url, 0):
                        available_gpu[crn_url] = 0
                    available_gpu[crn_url] += 1

        # If gpu is not available we checked if there is some but being used
        used_gpu: dict[str, int] = {}
        if len(available_gpu) == 0:
            for crn_url, gpus in network_gpu.used_gpu_list.items():
                for gpu in gpus:
                    if gpu.model == tier.model:
                        # On this dict we want only count if there is a GPU for simplify draw
                        if not used_gpu.get(crn_url, 0):
                            used_gpu[crn_url] = 0

                        used_gpu[crn_url] += 1
        return available_gpu, used_gpu

    def build_storage_and_website(
        self,
        price_dict,
        storage: bool = False,
    ):
        infos = []
        if "fixed" in price_dict:
            infos.append(
                Text.from_markup(
                    "Service & Availability (Holding): [orange1]"
                    f"{displayable_amount(price_dict.get('fixed'),decimals=3)}"
                    " tokens[/orange1]\n"
                )
            )
        if "storage" in price_dict and isinstance(price_dict["storage"], Price):
            prefix = "+ " if not storage else ""
            storage_price = price_dict["storage"]

            def fmt(value, unit):
                amount = Decimal(str(value)) if value else Decimal("0")
                return (
                    f"{displayable_amount(amount, decimals=5)} {unit}/Mib[/bright_cyan] -or- "
                    f"[bright_cyan]{displayable_amount(amount * 1024, decimals=5)} {unit}/GiB[/bright_cyan]"
                )

        holding = fmt(storage_price.holding, "token")

        lines = [f"{prefix}$ALEPH (Holding): [bright_cyan]{holding}"]

        # Show credits ONLY for storage, and only if a credit price exists
        if storage and storage_price.credit:
            credit = fmt(storage_price.credit, "credit")
            lines.append(f"Credits: [bright_cyan]{credit}")

        infos.append(Text.from_markup("\n".join(lines)))

        return Group(*infos)

    def build_column(
        self,
        entity: PricingEntity,
        entity_info: PricingPerEntity,
    ):
        # Common Column for PROGRAM / INSTANCE / CONF / GPU
        self.table.add_column("Tier", style="cyan")
        self.table.add_column("Compute Units", style="orchid")
        self.table.add_column("vCPUs", style="bright_cyan")
        self.table.add_column("RAM (GiB)", style="bright_cyan")
        self.table.add_column("Disk (GiB)", style="bright_cyan")

        # GPU Case
        if entity in PRICING_GROUPS[GroupEntity.GPU]:
            self.table.add_column("GPU Model", style="orange1")
            self.table.add_column("VRAM (GiB)", style="orange1")

        cu_price = entity_info.price.get("compute_unit")
        if isinstance(cu_price, Price) and cu_price.holding:
            self.table.add_column("$ALEPH (Holding)", style="red", justify="center")

        if isinstance(cu_price, Price) and cu_price.payg and entity in PAYG_GROUP:
            self.table.add_column("$ALEPH (Pay-As-You-Go)", style="green", justify="center")

        if isinstance(cu_price, Price) and cu_price.credit:
            self.table.add_column("$ Credits", style="green", justify="center")

        if entity in PRICING_GROUPS[GroupEntity.PROGRAM]:
            self.table.add_column("+ Internet Access", style="orange1", justify="center")

    def fill_tier(
        self,
        tier: Tier,
        entity: PricingEntity,
        entity_info: PricingPerEntity,
        network_gpu: Optional[NetworkGPUS] = None,
    ):
        tier_id = self._format_tier_id(tier.id)
        self.table.add_section()

        if not entity_info.compute_unit:
            error = f"No compute unit defined for tier {tier_id} in entity {entity}"
            raise ValueError(error)

        row = [
            tier_id,
            str(tier.compute_units),
            str(entity_info.compute_unit.vcpus),
            f"{entity_info.compute_unit.memory_mib * tier.compute_units / 1024:.0f}",
            f"{entity_info.compute_unit.disk_mib * tier.compute_units / 1024:.0f}",
        ]

        # Gpu Case
        if entity in PRICING_GROUPS[GroupEntity.GPU] and tier.model:
            if not network_gpu:  # No info about if it available on network
                row.append(tier.model)
            else:
                # Find how many of that GPU is currently available
                available_gpu, used_gpu = self._process_network_gpu_info(network_gpu=network_gpu, tier=tier)

                gpu_line = tier.model
                if available_gpu:
                    gpu_line += "[white] Available on: [/white]"
                    for crn_url, count in available_gpu.items():
                        gpu_line += f"\n[bright_yellow]• {crn_url}[/bright_yellow]: [white]{count}[/white]"
                elif used_gpu:
                    gpu_line += "[red] GPU Already in use: [/red]"
                    for crn_url, count in used_gpu.items():
                        if count > 0:
                            gpu_line += f"\n[orange]• {crn_url}[/orange][white]:[/white][orange] {count}[/orange]"
                else:
                    gpu_line += "[red] Currently not available on network[/red]"
                row.append(Text.from_markup(gpu_line))
            row.append(str(tier.vram))

        cu_price = entity_info.price.get("compute_unit")
        # Fill Holding row
        if isinstance(cu_price, Price) and cu_price.holding:
            if entity == PricingEntity.INSTANCE_CONFIDENTIAL or (
                entity == PricingEntity.INSTANCE and tier.compute_units > 4
            ):
                row.append(Text.from_markup("[red]Not Available[/red]"))
            else:
                row.append(
                    f"{displayable_amount(Decimal(str(cu_price.holding)) * tier.compute_units, decimals=3)} tokens"
                )
        # Fill PAYG row
        if isinstance(cu_price, Price) and cu_price.payg and entity in PAYG_GROUP:
            payg_price = cu_price.payg
            payg_hourly = Decimal(str(payg_price)) * tier.compute_units
            row.append(
                f"{displayable_amount(payg_hourly, decimals=3)} token/hour"
                f"\n{displayable_amount(payg_hourly * 24, decimals=3)} token/day"
            )
        # Fill Credit row
        if isinstance(cu_price, Price) and cu_price.credit:
            credit_price = cu_price.credit
            credit_hourly = Decimal(str(credit_price)) * tier.compute_units
            row.append(
                f"{displayable_amount(credit_hourly, decimals=3)} credit/hour"
                f"\n{displayable_amount(credit_hourly * 24, decimals=3)} credit/day"
            )

        # Program Case we additional price
        if entity in PRICING_GROUPS[GroupEntity.PROGRAM]:
            program_price = entity_info.price.get("compute_unit")
            if isinstance(program_price, Price) and program_price.holding is not None:
                amount = Decimal(str(program_price.holding)) * tier.compute_units * 2
                internet_cell = (
                    "✅ Included"
                    if entity == PricingEntity.PROGRAM_PERSISTENT
                    else f"{displayable_amount(amount)} tokens"
                )
                row.append(internet_cell)
            else:
                row.append("N/A")
        self.table.add_row(*row)

    def fill_column(
        self,
        entity: PricingEntity,
        entity_info: PricingPerEntity,
        network_gpu: Optional[NetworkGPUS],
        only_tier: Optional[int] = None,  # <-- now int
    ):
        any_added = False

        if not entity_info.tiers:
            error = f"No tiers defined for entity {entity}"
            raise ValueError(error)

        for tier in entity_info.tiers:
            if not self._tier_matches(tier, only_tier):
                continue
            self.fill_tier(tier=tier, entity=entity, entity_info=entity_info, network_gpu=network_gpu)
            any_added = True
        return any_added

    def display_table_for(
        self, entity: PricingEntity, network_gpu: Optional[NetworkGPUS] = None, tier: Optional[int] = None
    ):
        info = self.data[entity]
        label = self._format_name(entity=entity)
        price = info.price

        if entity in [PricingEntity.WEB3_HOSTING, PricingEntity.STORAGE]:
            displayable_group = self.build_storage_and_website(
                price_dict=price, storage=entity == PricingEntity.STORAGE
            )
            self.console.print(
                Panel(
                    displayable_group,
                    title=f"Pricing: {label}",
                    border_style="orchid",
                    expand=False,
                    title_align="left",
                )
            )
        else:
            # Create a new table for each entity
            table = Table(
                border_style="magenta",
                box=box.MINIMAL,
            )
            self.table = table

            self.build_column(entity=entity, entity_info=info)

            any_rows_added = self.fill_column(entity=entity, entity_info=info, network_gpu=network_gpu, only_tier=tier)

            # If no rows were added, the filter was too restrictive
            # So add all tiers without filter
            if not any_rows_added:
                self.fill_column(entity=entity, entity_info=info, network_gpu=network_gpu, only_tier=None)

            storage_price = info.price.get("storage")
            extra_price_holding = ""
            if isinstance(storage_price, Price) and storage_price.holding:
                extra_price_holding = (
                    f"[red]{displayable_amount(Decimal(str(storage_price.holding)) * 1024, decimals=5)}"
                    " token/GiB[/red] (Holding) -or- "
                )

            payg_storage_price = "0"
            if isinstance(storage_price, Price) and storage_price.payg:
                payg_storage_price = displayable_amount(Decimal(str(storage_price.payg)) * 1024 * 24, decimals=5)

            extra_price_credits = "0"
            if isinstance(storage_price, Price) and storage_price.credit:
                extra_price_credits = displayable_amount(Decimal(str(storage_price.credit)) * 1024 * 24, decimals=5)

            infos = [
                Text.from_markup(
                    f"Extra Volume Cost: {extra_price_holding}"
                    f"[green]{payg_storage_price}"
                    " token/GiB/day[/green] (Pay-As-You-Go)"
                    f" -or- [green]{extra_price_credits} credit/GiB/day[/green] (Credits)\n"
                )
            ]
            displayable_group = Group(
                self.table,
                Text.assemble(*infos),
            )

            self.console.print(
                Panel(
                    displayable_group,
                    title=f"Pricing: {label}",
                    border_style="orchid",
                    expand=False,
                    title_align="left",
                )
            )


@async_lru_cache
async def fetch_pricing_aggregate() -> Pricing:
    """Fetch pricing aggregate and format it as Pricing"""
    async with AlephHttpClient(api_server=settings.API_HOST) as client:
        pricing = await client.pricing.get_pricing_aggregate()

    return Pricing(pricing)


async def prices_for_service(
    service: Annotated[GroupEntity, typer.Argument(help="Service to display pricing for")],
    tier: Annotated[Optional[int], typer.Option(help="Service specific Tier")] = None,
    json: Annotated[bool, typer.Option(help="JSON output instead of Rich Table")] = False,
    no_null: Annotated[bool, typer.Option(help="Exclude null values in JSON output")] = False,
    with_current_availability: Annotated[
        bool,
        typer.Option(
            "--with-current-availability/--ignore-availability",
            help="(GPU only) Show prices only for GPU types currently accessible on the network.",
        ),
    ] = False,
    debug: bool = False,
):
    """Display pricing for services available on aleph.im & twentysix.cloud"""

    setup_logging(debug)

    group: list[PricingEntity] = PRICING_GROUPS[service]

    pricing = await fetch_pricing_aggregate()
    # Fetch Current availibity
    network_gpu = None
    if (service in [GroupEntity.GPU, GroupEntity.ALL]) and with_current_availability:
        from aleph_client.commands.instance.network import call_program_crn_list

        crn_lists = await call_program_crn_list()
        network_gpu = crn_lists.find_gpu_on_network()
    if json:
        for entity in group:
            typer.echo(
                colorful_json(
                    pricing.data[entity].model_dump_json(
                        indent=4,
                        exclude_none=no_null,
                    )
                )
            )
    else:
        for entity in group:
            pricing.display_table_for(entity, network_gpu=network_gpu, tier=tier)
