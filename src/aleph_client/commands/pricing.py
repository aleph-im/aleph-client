from __future__ import annotations

import logging
from decimal import Decimal
from enum import Enum
from typing import Annotated, Optional

import aiohttp
import typer
from aleph.sdk.conf import settings
from aleph.sdk.utils import displayable_amount, safe_getattr
from pydantic import BaseModel
from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from aleph_client.commands.utils import setup_logging, validated_prompt
from aleph_client.utils import async_lru_cache, sanitize_url

logger = logging.getLogger(__name__)

pricing_link = (
    f"{sanitize_url(settings.API_HOST)}/api/v0/aggregates/0xFba561a84A537fCaa567bb7A2257e7142701ae2A.json?keys=pricing"
)


class PricingEntity(str, Enum):
    STORAGE = "storage"
    WEB3_HOSTING = "web3_hosting"
    PROGRAM = "program"
    PROGRAM_PERSISTENT = "program_persistent"
    INSTANCE = "instance"
    INSTANCE_CONFIDENTIAL = "instance_confidential"
    INSTANCE_GPU_STANDARD = "instance_gpu_standard"
    INSTANCE_GPU_PREMIUM = "instance_gpu_premium"


class GroupEntity(str, Enum):
    STORAGE = "storage"
    WEBSITE = "website"
    PROGRAM = "program"
    INSTANCE = "instance"
    CONFIDENTIAL = "confidential"
    GPU = "gpu"
    ALL = "all"


PRICING_GROUPS: dict[str, list[PricingEntity]] = {
    GroupEntity.STORAGE: [PricingEntity.STORAGE],
    GroupEntity.WEBSITE: [PricingEntity.WEB3_HOSTING],
    GroupEntity.PROGRAM: [PricingEntity.PROGRAM, PricingEntity.PROGRAM_PERSISTENT],
    GroupEntity.INSTANCE: [PricingEntity.INSTANCE],
    GroupEntity.CONFIDENTIAL: [PricingEntity.INSTANCE_CONFIDENTIAL],
    GroupEntity.GPU: [PricingEntity.INSTANCE_GPU_STANDARD, PricingEntity.INSTANCE_GPU_PREMIUM],
    GroupEntity.ALL: list(PricingEntity),
}

PAYG_GROUP: list[PricingEntity] = [
    PricingEntity.INSTANCE,
    PricingEntity.INSTANCE_CONFIDENTIAL,
    PricingEntity.INSTANCE_GPU_STANDARD,
    PricingEntity.INSTANCE_GPU_PREMIUM,
]

MAX_VALUE = Decimal(999_999_999)


class SelectedTierPrice(BaseModel):
    hold: Decimal
    payg: Decimal  # Token by second
    storage: Optional[SelectedTierPrice]


class SelectedTier(BaseModel):
    tier: int
    compute_units: int
    vcpus: int
    memory: int
    disk: int
    gpu_model: Optional[str]
    price: SelectedTierPrice


class Pricing:
    def __init__(self, **kwargs):
        self.data = kwargs.get("data", {}).get("pricing", {})

    def display_table_for(
        self,
        pricing_entity: Optional[PricingEntity] = None,
        compute_units: Optional[int] = 0,
        vcpus: Optional[int] = 0,
        memory: Optional[int] = 0,
        gpu_models: Optional[dict[str, dict[str, dict[str, int]]]] = None,
        persistent: Optional[bool] = None,
        selector: bool = False,
        exit_on_error: bool = True,
        verbose: bool = True,
    ) -> Optional[SelectedTier]:
        """Display pricing table for an entity"""

        if not compute_units:
            compute_units = 0
        if not vcpus:
            vcpus = 0
        if not memory:
            memory = 0

        if not pricing_entity:
            if persistent is not None:
                # Program entity selection: Persistent or Non-Persistent
                pricing_entity = PricingEntity.PROGRAM_PERSISTENT if persistent else PricingEntity.PROGRAM

        entity_name = safe_getattr(pricing_entity, "value")
        if pricing_entity:
            entity = self.data.get(entity_name)
            label = entity_name.replace("_", " ").title()
        else:
            logger.error(f"Entity {entity_name} not found")
            if exit_on_error:
                raise typer.Exit(1)
            else:
                return None

        unit = entity.get("compute_unit", {})
        unit_vcpus = unit.get("vcpus")
        unit_memory = unit.get("memory_mib")
        unit_disk = unit.get("disk_mib")
        price = entity.get("price", {})
        price_unit = price.get("compute_unit")
        price_storage = price.get("storage")
        price_fixed = price.get("fixed")
        tiers = entity.get("tiers", [])

        displayable_group = None
        tier_data: dict[int, SelectedTier] = {}
        auto_selected = (compute_units or vcpus or memory) and not gpu_models
        if tiers:
            if auto_selected:
                tiers = [
                    tier
                    for tier in tiers
                    if compute_units <= tier["compute_units"]
                    and vcpus <= unit_vcpus * tier["compute_units"]
                    and memory <= unit_memory * tier["compute_units"]
                ]
                if tiers:
                    tiers = tiers[:1]
                else:
                    requirements = []
                    if compute_units:
                        requirements.append(f"compute_units>={compute_units}")
                    if vcpus:
                        requirements.append(f"vcpus>={vcpus}")
                    if memory:
                        requirements.append(f"memory>={memory}")
                    typer.echo(
                        f"Minimum tier with required {' & '.join(requirements)}"
                        f" not found for {pricing_entity.value}"
                    )
                    if exit_on_error:
                        raise typer.Exit(1)
                    else:
                        return None

            table = Table(
                border_style="magenta",
                box=box.MINIMAL,
            )
            table.add_column("Tier", style="cyan")
            table.add_column("Compute Units", style="orchid")
            table.add_column("vCPUs", style="bright_cyan")
            table.add_column("RAM (GiB)", style="bright_cyan")
            table.add_column("Disk (GiB)", style="bright_cyan")
            if "model" in tiers[0]:
                table.add_column("GPU Model", style="orange1")
            if "vram" in tiers[0]:
                table.add_column("VRAM (GiB)", style="orange1")
            if "holding" in price_unit:
                table.add_column("$ALEPH (Holding)", style="red", justify="center")
            if "payg" in price_unit and pricing_entity in PAYG_GROUP:
                table.add_column("$ALEPH (Pay-As-You-Go)", style="green", justify="center")
            if pricing_entity in PRICING_GROUPS[GroupEntity.PROGRAM]:
                table.add_column("+ Internet Access", style="orange1", justify="center")

            for tier in tiers:
                tier_id = tier["id"].split("-", 1)[1]
                current_units = tier["compute_units"]
                table.add_section()
                row = [
                    tier_id,
                    str(current_units),
                    str(unit_vcpus * current_units),
                    f"{unit_memory * current_units / 1024:.0f}",
                    f"{unit_disk * current_units / 1024:.0f}",
                ]
                if "model" in tier:
                    if gpu_models is None:
                        row.append(tier["model"])
                    elif tier["model"] in gpu_models:
                        gpu_line = tier["model"]
                        for device, details in gpu_models[tier["model"]].items():
                            gpu_line += f"\n[bright_yellow]• {device}[/bright_yellow]\n"
                            gpu_line += f"  [grey50]↳ [white]{details['count']}[/white]"
                            gpu_line += f" available on [white]{details['on_crns']}[/white] CRN(s)[/grey50]"
                        row.append(Text.from_markup(gpu_line))
                    else:
                        continue
                if "vram" in tier:
                    row.append(f"{tier['vram'] / 1024:.0f}")
                if "holding" in price_unit:
                    row.append(
                        f"{displayable_amount(Decimal(price_unit['holding']) * current_units, decimals=3)} tokens"
                    )
                if "payg" in price_unit and pricing_entity in PAYG_GROUP:
                    payg_hourly = Decimal(price_unit["payg"]) * current_units
                    row.append(
                        f"{displayable_amount(payg_hourly, decimals=3)} token/hour"
                        f"\n{displayable_amount(payg_hourly*24, decimals=3)} token/day"
                    )
                if pricing_entity in PRICING_GROUPS[GroupEntity.PROGRAM]:
                    internet_cell = (
                        "✅ Included"
                        if pricing_entity == PricingEntity.PROGRAM_PERSISTENT
                        else f"{displayable_amount(Decimal(price_unit['holding']) * current_units * 2)} tokens"
                    )
                    row.append(internet_cell)
                table.add_row(*row)

                tier_data[tier_id] = SelectedTier(
                    tier=tier_id,
                    compute_units=current_units,
                    vcpus=unit_vcpus * current_units,
                    memory=unit_memory * current_units,
                    disk=unit_disk * current_units,
                    gpu_model=tier.get("model"),
                    price=SelectedTierPrice(
                        hold=Decimal(price_unit["holding"]) * current_units if "holding" in price_unit else MAX_VALUE,
                        payg=Decimal(price_unit["payg"]) / 3600 * current_units if "payg" in price_unit else MAX_VALUE,
                        storage=SelectedTierPrice(
                            hold=Decimal(price_storage["holding"]) if "holding" in price_storage else MAX_VALUE,
                            payg=Decimal(price_storage["payg"]) / 3600 if "payg" in price_storage else MAX_VALUE,
                            storage=None,
                        ),
                    ),
                )

            extra_price_holding = (
                f"[red]{displayable_amount(Decimal(price_storage['holding'])*1024, decimals=5)}"
                " token/GiB[/red] (Holding) -or- "
                if "holding" in price_storage
                else ""
            )
            infos = [
                Text.from_markup(
                    f"Extra Volume Cost: {extra_price_holding}"
                    f"[green]{displayable_amount(Decimal(price_storage['payg'])*1024*24, decimals=5)}"
                    " token/GiB/day[/green] (Pay-As-You-Go)"
                )
            ]
            displayable_group = Group(
                table,
                Text.assemble(*infos),
            )
        else:
            infos = [Text("\n")]
            if price_fixed:
                infos.append(
                    Text.from_markup(
                        f"Service & Availability (Holding): [orange1]{displayable_amount(price_fixed, decimals=3)}"
                        " tokens[/orange1]\n\n+ "
                    )
                )
            infos.append(
                Text.from_markup(
                    "$ALEPH (Holding): [bright_cyan]"
                    f"{displayable_amount(Decimal(price_storage['holding']), decimals=5)}"
                    " token/Mib[/bright_cyan] -or- [bright_cyan]"
                    f"{displayable_amount(Decimal(price_storage['holding'])*1024, decimals=5)}"
                    " token/GiB[/bright_cyan]"
                )
            )
            displayable_group = Group(
                Text.assemble(*infos),
            )

        if gpu_models and not tier_data:
            typer.echo(f"No GPU available for {label} at the moment.")
            raise typer.Exit(1)
        elif verbose:
            console = Console()
            console.print(
                Panel(
                    displayable_group,
                    title=f"Pricing: {'Selected ' if compute_units else ''}{label}",
                    border_style="orchid",
                    expand=False,
                    title_align="left",
                )
            )

        if selector and pricing_entity not in [PricingEntity.STORAGE, PricingEntity.WEB3_HOSTING]:
            if not auto_selected:
                tier_id = validated_prompt("Select a tier by index", lambda tier_id: tier_id in tier_data)
            return next(iter(tier_data.values())) if auto_selected else tier_data[tier_id]

        return None


@async_lru_cache
async def fetch_pricing() -> Pricing:
    """Fetch pricing aggregate and format it as Pricing"""

    async with aiohttp.ClientSession() as session:
        async with session.get(pricing_link) as resp:
            if resp.status != 200:
                logger.error("Unable to fetch pricing aggregate")
                raise typer.Exit(1)

            data = await resp.json()
            return Pricing(**data)


async def prices_for_service(
    service: Annotated[GroupEntity, typer.Argument(help="Service to display pricing for")],
    compute_units: Annotated[int, typer.Option(help="Compute units to display pricing for")] = 0,
    debug: bool = False,
):
    """Display pricing for services available on aleph.im & twentysix.cloud"""

    setup_logging(debug)

    group = PRICING_GROUPS[service]
    pricing = await fetch_pricing()
    for entity in group:
        pricing.display_table_for(entity, compute_units=compute_units, exit_on_error=False)
