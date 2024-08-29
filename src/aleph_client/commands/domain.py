from __future__ import annotations

from pathlib import Path
from time import sleep
from typing import Dict, Optional, cast

import typer
from aleph.sdk.account import _load_account
from aleph.sdk.client import AlephHttpClient, AuthenticatedAlephHttpClient
from aleph.sdk.conf import settings
from aleph.sdk.domain import (
    DomainValidator,
    Hostname,
    TargetType,
    get_target_type,
    hostname_from_url,
)
from aleph.sdk.exceptions import DomainConfigurationError
from aleph.sdk.query.filters import MessageFilter
from aleph.sdk.types import AccountFromPrivateKey
from aleph_message.models import AggregateMessage
from aleph_message.models.base import MessageType
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table

from aleph_client.commands import help_strings
from aleph_client.commands.utils import is_environment_interactive
from aleph_client.utils import AsyncTyper

app = AsyncTyper(no_args_is_help=True)


async def get_aggregate_domain_info(account, fqdn):
    async with AlephHttpClient(api_server=settings.API_HOST) as client:
        aggregates = await client.get_messages(
            message_filter=MessageFilter(
                addresses=[str(account.get_address())],
                message_types=[MessageType.aggregate],
            ),
            page=1,
            page_size=1000,
        )

        for message in aggregates.messages:
            aggregate = cast(AggregateMessage, message)
            if aggregate.content.key == "domains":
                for domain, info in aggregate.content.content.items():
                    if domain == fqdn:
                        return {"timestamp": aggregate.content.time, "info": info}
        return None


async def check_domain_records(fqdn, target, owner):
    domain_validator = DomainValidator()
    try:
        status = await domain_validator.check_domain(fqdn, target, owner)
    except DomainConfigurationError as msg:
        help_, err, status = msg.args[0]

    return status


async def attach_resource(
    account: AccountFromPrivateKey,
    fqdn: Hostname,
    item_hash: Optional[str] = None,
    catch_all_path: Optional[str] = None,
    interactive: Optional[bool] = None,
):
    interactive = is_environment_interactive() if interactive is None else interactive

    domain_info = await get_aggregate_domain_info(account, fqdn)
    console = Console()

    while not item_hash:
        item_hash = Prompt.ask("Enter Hash reference of the resource to attach")

    table = Table(title=f"Attach resource to: {fqdn}")
    table.add_column("Current resource", justify="right", style="red", no_wrap=True)
    table.add_column("New resource", justify="right", style="green", no_wrap=True)
    table.add_column("Resource type", style="magenta")

    """
    Detect target type on the fly to be able to switch to another type
    """
    resource_type = await get_target_type(fqdn)

    if resource_type == TargetType.IPFS and not catch_all_path:
        catch_all_path = Prompt.ask("Catch all path? ex: /404.html or press [Enter] to ignore", default=None)

    if domain_info is not None and domain_info.get("info"):
        current_resource = domain_info["info"]["message_id"]
    else:
        current_resource = "null"

    table.add_row(
        f"{current_resource[:16]}...{current_resource[-16:]}",
        f"{item_hash[:16]}...{item_hash[-16:]}",
        resource_type,
    )

    console.print(table)

    if (not interactive) or Confirm.ask("Continue"):
        """Create aggregate message"""

        async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:

            options: Optional[Dict] = None
            if catch_all_path and catch_all_path.startswith("/"):
                options = {"catch_all_path": catch_all_path}

            aggregate_content = {
                str(fqdn): {
                    "message_id": item_hash,
                    "type": resource_type,
                    # console page compatibility
                    "programType": resource_type,
                    "options": options,
                }
            }

            if catch_all_path and catch_all_path.startswith("/"):
                aggregate_content[fqdn]["options"] = {"catch_all_path": catch_all_path}

            aggregate_message, message_status = await client.create_aggregate(
                key="domains", content=aggregate_content, channel="ALEPH-CLOUDSOLUTIONS"
            )

            console.log("[green bold]Resource attached!")
            console.log(
                f"Visualise on: https://explorer.aleph.im/address/ETH/{account.get_address()}/message/AGGREGATE/{aggregate_message.item_hash}"
            )


async def detach_resource(account: AccountFromPrivateKey, fqdn: Hostname, interactive: Optional[bool] = None):
    domain_info = await get_aggregate_domain_info(account, fqdn)
    interactive = is_environment_interactive() if interactive is None else interactive

    console = Console()

    table = Table(title=f"Detach resource of: {fqdn}")
    table.add_column("Current resource", justify="right", style="red", no_wrap=True)
    table.add_column("New resource", justify="right", style="green", no_wrap=True)
    table.add_column("Resource type", style="magenta")

    if domain_info is not None and domain_info.get("info"):
        current_resource = domain_info["info"]["message_id"]
    else:
        current_resource = "null"

    resource_type = await get_target_type(fqdn)
    table.add_row(f"{current_resource[:16]}...{current_resource[-16:]}", "", resource_type)

    console.print(table)

    if (not interactive) or Confirm.ask("Continue"):
        """Update aggregate message"""

        async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
            aggregate_content = {str(fqdn): None}

            aggregate_message, message_status = await client.create_aggregate(
                key="domains", content=aggregate_content, channel="ALEPH-CLOUDSOLUTIONS"
            )

            console.log("[green bold]Resource detached!")
            console.log(
                f"Visualise on: https://explorer.aleph.im/address/ETH/{account.get_address()}/message/AGGREGATE/{aggregate_message.item_hash}"
            )


@app.command()
async def add(
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    fqdn: str = typer.Argument(..., help=help_strings.CUSTOM_DOMAIN_NAME),
    target: Optional[TargetType] = typer.Option(None, help=help_strings.CUSTOM_DOMAIN_TARGET_TYPES),
    item_hash: Optional[str] = typer.Option(None, help=help_strings.CUSTOM_DOMAIN_ITEM_HASH),
    owner: Optional[str] = typer.Option(None, help=help_strings.CUSTOM_DOMAIN_OWNER_ADDRESS),
    ask: bool = typer.Option(default=True, help=help_strings.ASK_FOR_CONFIRMATION),
):
    """Add and link a Custom Domain."""
    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)
    interactive = False if (not ask) else is_environment_interactive()

    console = Console()
    domain_validator = DomainValidator()
    fqdn = hostname_from_url(fqdn)

    while target is None:
        target = TargetType(
            Prompt.ask(
                "Select a target resource type",
                choices=[TargetType.IPFS, TargetType.PROGRAM, TargetType.INSTANCE],
            )
        )
    selected_target: TargetType = target

    table = Table(title=f"Required DNS entries for: {fqdn}")

    table.add_column("RECORD ID", justify="right", style="cyan", no_wrap=True)
    table.add_column("DNS TYPE", justify="right", style="cyan", no_wrap=True)
    table.add_column("DNS NAME", style="magenta")
    table.add_column("DNS VALUE", justify="right", style="green")

    owner = owner or account.get_address()
    dns_rules = domain_validator.get_required_dns_rules(fqdn, selected_target, owner)
    for rule_id, rule in enumerate(dns_rules):
        table.add_row(str(rule_id), rule.dns["type"], rule.dns["name"], rule.dns["value"])

    console.print(table)

    msg_status = "[bold green]Detecting dns..."

    with console.status(msg_status) as status:
        max_retries = 5
        while dns_rules:
            rule = dns_rules[0]
            """Get rules check status"""
            checks = await check_domain_records(fqdn, target, owner)
            completed_rules = []
            for index, rule in enumerate(dns_rules):
                if checks[rule.name] is True:
                    """Pass configured rules"""
                    completed_rules.append(rule)
                    console.log(f"record: {index} [bold green] OK")

            for _rule in completed_rules:
                dns_rules.remove(_rule)
                completed_rules = []

            if dns_rules:
                rule = dns_rules[0]
                console.log(f"[green]{rule.info}")
                status.update(f"{msg_status} [bold red]{rule.on_error}")

                max_retries -= 1
                sleep(10)

            if max_retries == 0:
                status.stop()
                continue_ = (not interactive) or Confirm.ask("Continue?")
                if continue_:
                    status.start()
                    max_retries = 5
                else:
                    raise typer.Exit()

    """Attach option"""
    if (not interactive) or Confirm.ask(f"Attach resource to [bold green]{fqdn}"):
        await attach_resource(account, fqdn, item_hash)

    raise typer.Exit()


@app.command()
async def attach(
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    fqdn: str = typer.Argument(..., help=help_strings.CUSTOM_DOMAIN_NAME),
    item_hash: Optional[str] = typer.Option(None, help=help_strings.CUSTOM_DOMAIN_ITEM_HASH),
    catch_all_path: str = typer.Option(default=None, help=help_strings.IPFS_CATCH_ALL_PATH),
    ask: bool = typer.Option(default=True, help=help_strings.ASK_FOR_CONFIRMATION),
):
    """Attach resource to a Custom Domain."""
    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    await attach_resource(
        account,
        Hostname(fqdn),
        item_hash,
        interactive=False if (not ask) else None,
        catch_all_path=catch_all_path,
    )
    raise typer.Exit()


@app.command()
async def detach(
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    fqdn: str = typer.Argument(..., help=help_strings.CUSTOM_DOMAIN_NAME),
    ask: bool = typer.Option(default=True, help=help_strings.ASK_FOR_CONFIRMATION),
):
    """Unlink Custom Domain."""
    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    await detach_resource(account, Hostname(fqdn), interactive=False if (not ask) else None)
    raise typer.Exit()


@app.command()
async def info(
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    fqdn: str = typer.Argument(..., help=help_strings.CUSTOM_DOMAIN_NAME),
):
    """Show Custom Domain Details."""
    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    console = Console()
    domain_validator = DomainValidator()

    domain_info = await get_aggregate_domain_info(account, fqdn)
    if domain_info is None or domain_info.get("info") is None:
        console.log(f"Domain: {fqdn} not configured")
        raise typer.Exit()

    table = Table(title=f"Domain info: {fqdn}")
    table.add_column("Resource type", justify="right", style="cyan", no_wrap=True)
    table.add_column("Attached resource", justify="right", style="cyan", no_wrap=True)

    resource_type = TargetType(domain_info["info"]["type"])
    table_values = [resource_type, domain_info["info"]["message_id"]]

    options = domain_info["info"].get("options")
    if resource_type == TargetType.IPFS and options and "catch_all_path" in options:
        table.add_column("Catch all path", justify="right", style="cyan", no_wrap=True)
        print(domain_info)
        table_values.append(domain_info["info"]["options"]["catch_all_path"])
    elif resource_type == TargetType.PROGRAM:
        table.add_column("Target resource", justify="right", style="cyan", no_wrap=True)
        table_values.append(domain_info["info"]["message_id"])
    if resource_type == TargetType.INSTANCE:
        table.add_column("Target resource", justify="right", style="cyan", no_wrap=True)
        ips = await domain_validator.get_ipv6_addresses(Hostname(fqdn))
        table_values.append(",".join([str(ip) for ip in ips]))

    table.add_row(*table_values)
    console.print(table)
    raise typer.Exit()
