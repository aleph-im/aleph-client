import asyncio
import logging
from functools import wraps
from pathlib import Path
from time import sleep
from typing import Optional

import typer
from aleph.sdk.account import _load_account
from aleph.sdk.conf import settings as sdk_settings
from aleph.sdk.domain import DomainValidator
from aleph.sdk.exceptions import DomainConfigurationError
from aleph_client.commands import help_strings
from aleph_client.commands.loader import Loader
from pydantic import BaseModel
from typer.colors import GREEN, RED


def coro(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))

    return wrapper


app = typer.Typer()

@app.command()
def add(
    private_key: Optional[str] = typer.Option(
        sdk_settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY
    ),
    private_key_file: Optional[Path] = typer.Option(
        sdk_settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE
    ),
    domain_name: str = typer.Argument(..., help=help_strings.CUSTOM_DOMAIN_NAME),
    item_hash: str = typer.Argument(..., help=help_strings.CUSTOM_DOMAIN_ITEM_HASH),
    target_type: Optional[str] = typer.Option("program", help=help_strings.CUSTOM_DOMAIN_TARGET_TYPE),
    owner: Optional[str] = typer.Option(None, help=help_strings.CUSTOM_DOMAIN_OWNER_ADDRESS)
):
    """Add and link a Custom Domain."""
    account: AccountFromPrivateKey = _load_account(private_key, private_key_file)
    print("<<<<<<")

    #loop = asyncio.new_event_loop()
    domain_validator = DomainValidator()

    dns_rules = aleph_dns.get_required_dns_rules(domain_name, target_type)

    typer.secho(dns_rules[0]["info"], fg=typer.colors.YELLOW)
    input("press any key to continue")

    max_retries = 10
    while max_retries >= 0:
        domain_check = check_configuration(aleph_dns, domain_name, target_type)
        if domain_check is True:
            break
        sleep(5)
        max_retries -= 1
        #if max_retries == 8:
        typer.secho(domain_check[0], fg=RED)

    if domain_check is not True:
        typer.echo(domain_check[0])
#        print("res:", domain_check)
    # check if item hash exists
    #message =

    # check domain and follow steps



def check_configuration(aleph_dns, domain_name, target_type):
    try:
        with Loader("Domain configuration check"):
            sleep(2)
            domain_status = asyncio.run(aleph_dns.check_domain(domain_name, target_type))
            return True
    except DomainConfigurationError as error:
        return error.args[0]

@app.command()
@coro
async def info(
        domain_name: str = typer.Argument(..., help=help_strings.CUSTOM_DOMAIN_NAME)
):
    domain_validator = DomainValidator()
    target = None
    try:
        res = await domain_validator.resolver.query(domain_name, "CNAME")
        cname_value = res.cname
        if sdk_settings.DNS_IPFS_DOMAIN in cname_value:
            target = "ipfs"
        elif sdk_settings.DNS_PROGRAM_DOMAIN in cname_value:
            target = "program"
        elif sdk_settings.DNS_INSTANCE_DOMAIN in cname_value:
            target = "instance"
    except Exception:
        typer.echo(f"Domain: {domain_name} not configured")
        raise typer.Exit()

    print(target)
    if target is not None:
        try:
            status = await domain_validator.check_domain(domain_name, target)
            print(status)
            if target == "ipfs":
                pass
            elif target == "program":
                pass
            if target == "instance":
                ipv6 = domain_validator.get_ipv6_addresses(domain_name)
                typer.echo()
        except Exception:
            typer.Exit()
    else:
        raise typer.Exit()
