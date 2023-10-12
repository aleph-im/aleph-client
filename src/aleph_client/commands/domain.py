from pathlib import Path
from time import sleep
from typing import Optional, cast

import typer
from aleph.sdk.account import _load_account
from aleph.sdk.client import AlephClient, AuthenticatedAlephClient
from aleph.sdk.conf import settings as sdk_settings
from aleph.sdk.domain import DomainValidator, Hostname, TargetType, hostname_from_url
from aleph.sdk.exceptions import DomainConfigurationError
from aleph.sdk.types import AccountFromPrivateKey
from aleph_client.commands import help_strings
from aleph_client.commands.utils import coro
from aleph_message.models import AggregateMessage, MessageType
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table

app = typer.Typer()


async def get_aggregate_domain_info(account, fqdn):
    async with AlephClient(api_server=sdk_settings.API_HOST) as client:
        aggregates = await client.get_messages(
            addresses=[str(account.get_address())],
            message_type=MessageType.aggregate,
            page=1,
            pagination=1000
        )

        for message in aggregates.messages:
            aggregate = cast(AggregateMessage, message)
            if aggregate.content.key == "domains":
                for domain, info in aggregate.content.content.items():
                    print("===", domain, fqdn)
                    if domain == fqdn:
                        return {
                            "timestamp": aggregate.content.time,
                            "info": info
                        }
        return None


async def check_domain_records(fqdn, target, owner):
    domain_validator = DomainValidator()
    try:
        status = await domain_validator.check_domain(fqdn, target, owner)
    except DomainConfigurationError as msg:
        help_, err, status = msg.args[0]

    return status


async def attach_resource(account: AccountFromPrivateKey, fqdn: Hostname, item_hash: Optional[str] = None, detach: Optional[bool] = False):
    domain_info = await get_aggregate_domain_info(account, fqdn)
    console = Console()

    while not item_hash and detach is False:
        item_hash = Prompt.ask("Enter Hash reference of the resource to attach")

    table = Table(title=f"Attach resource to: {fqdn}")
    table.add_column("Current resource", justify="right", style="red", no_wrap=True)
    table.add_column("New resource", justify="right", style="green", no_wrap=True)
    table.add_column("Resource type", style="magenta")

    current_resource = "null"
    domain_validator = DomainValidator()

    """
    Detect target type on the fly to be able to switch to another type
    """
    resource_type = await domain_validator.get_target_type(fqdn)

    if domain_info is not None and domain_info.get("info"):
        current_resource = domain_info["info"]["message_id"]

    table.add_row(f"{current_resource[:16]}...{current_resource[-16:]}", f"{item_hash[:16]}...{item_hash[-16:]}", resource_type)

    console.print(table)

    if Confirm.ask("Continue"):
        """Create aggregate message"""

        async with AuthenticatedAlephClient(
                account=account, api_server=sdk_settings.API_HOST
        ) as client:
            if detach:
                aggregate_content = {
                    fqdn: None
                }
            else:
                aggregate_content = {
                    fqdn: {
                        "message_id": item_hash,
                        "type": resource_type,
                        # console page compatibility
                        "programType": resource_type
                    }
                }

            aggregate_message, message_status = await client.create_aggregate(
                key="domains",
                content=aggregate_content,
                channel="ALEPH-CLOUDSOLUTIONS"
            )

            console.log("[green bold]Aleph message created!")
            console.log(f"Visualise on: https://explorer.aleph.im/address/ETH/{account.get_address()}/message/AGGREGATE/{aggregate_message.item_hash}")


@app.command()
@coro
async def add(
    private_key: Optional[str] = typer.Option(
        sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY
    ),
    private_key_file: Optional[Path] = typer.Option(
        sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE
    ),
    fqdn: str = typer.Argument(..., help=help_strings.CUSTOM_DOMAIN_NAME
                                      ),
    target: Optional[TargetType] = typer.Option(None,
                            help=help_strings.CUSTOM_DOMAIN_TARGET_TYPES),
    item_hash: Optional[str] = typer.Option(None, help=help_strings.CUSTOM_DOMAIN_ITEM_HASH),
    owner: Optional[str] = typer.Option(None, help=help_strings.CUSTOM_DOMAIN_OWNER_ADDRESS)
):
    """Add and link a Custom Domain."""
    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    console = Console()
    domain_validator = DomainValidator()
    fqdn = hostname_from_url(fqdn)

    if target is None:
        target = Prompt.ask("Select a resource type", choices={i.name.lower(): i.value.lower() for i in TargetType})

    table = Table(title=f"Required DNS entries for: {fqdn}")

    table.add_column("RECORD ID", justify="right", style="cyan", no_wrap=True)
    table.add_column("DNS TYPE", justify="right", style="cyan", no_wrap=True)
    table.add_column("DNS NAME", style="magenta")
    table.add_column("DNS VALUE", justify="right", style="green")

    owner = account.get_address()
    dns_rules = domain_validator.get_required_dns_rules(fqdn, target, owner)
    for rule_id, rule in enumerate(dns_rules):
        table.add_row(str(rule_id), rule["dns"]["type"], rule["dns"]["name"], rule["dns"]["value"])

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
                if checks[rule["rule_name"]] is True:
                    """Pass configured rules"""
                    completed_rules.append(rule)
                    console.log(f"record: {index} [bold green] OK")

            for _rule in completed_rules:
                dns_rules.remove(_rule)
                completed_rules = []

            if dns_rules:
                rule = dns_rules[0]
                console.log(f"[green]{rule['info']}")
                status.update(f"{msg_status} [bold red]{rule['on_error']}")

                max_retries -= 1
                sleep(10)

            if max_retries == 0:
                status.stop()
                continue_ = Confirm.ask("Continue?")
                if continue_:
                    status.start()
                    max_retries = 5
                else:
                    raise typer.Exit()

    """Attach option"""
    if Confirm.ask(f"Attach ressource to [bold green]{fqdn}"):
        await attach_resource(account, fqdn, item_hash)

    raise typer.Exit()


@app.command()
@coro
async def attach(
    private_key: Optional[str] = typer.Option(
        sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY
    ),
    private_key_file: Optional[Path] = typer.Option(
        sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE
    ),
    fqdn: str = typer.Argument(..., help=help_strings.CUSTOM_DOMAIN_NAME),
    item_hash: Optional[str] = typer.Option(None, help=help_strings.CUSTOM_DOMAIN_ITEM_HASH),
):
    """Attach resource to a Custom Domain."""
    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    await attach_resource(account, fqdn, item_hash)
    raise typer.Exit()

@app.command()
@coro
async def detach(
    private_key: Optional[str] = typer.Option(
        sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY
    ),
    private_key_file: Optional[Path] = typer.Option(
        sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE
    ),
    fqdn: str = typer.Argument(..., help=help_strings.CUSTOM_DOMAIN_NAME)
):
    """Unlink Custom Domain."""
    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)

    await attach_resource(account, fqdn, None, True)
    raise typer.Exit()


@app.command()
@coro
async def info(
    private_key: Optional[str] = typer.Option(
        sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY
    ),
    private_key_file: Optional[Path] = typer.Option(
        sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE
    ),
    fqdn: str = typer.Argument(..., help=help_strings.CUSTOM_DOMAIN_NAME)
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
    table.add_column("Final resource", justify="right", style="cyan", no_wrap=True)

    resource_type = TargetType(domain_info["info"]["type"])
    final_resource = "Unknown"

    try:
        if resource_type == TargetType.IPFS:
            final_resource = ""
        elif resource_type == TargetType.PROGRAM:
            final_resource = domain_info["info"]["message_id"]
        if resource_type == TargetType.INSTANCE:
            ips = await domain_validator.get_ipv6_addresses(fqdn)
            final_resource = ",".join(ips)
    except Exception:
        pass

    table.add_row(resource_type, domain_info["info"]["message_id"], final_resource)

    console.print(table)
    raise typer.Exit()
