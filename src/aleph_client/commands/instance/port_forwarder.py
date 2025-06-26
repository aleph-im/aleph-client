from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated, Optional

import typer
from aiohttp import ClientResponseError
from aleph.sdk import AlephHttpClient, AuthenticatedAlephHttpClient
from aleph.sdk.account import _load_account
from aleph.sdk.conf import settings
from aleph.sdk.exceptions import MessageNotProcessed, NotAuthorize
from aleph.sdk.types import InstanceManual, PortFlags, Ports
from aleph_message.models import Chain, InstanceMessage, ItemHash
from aleph_message.status import MessageStatus
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from aleph_client.commands import help_strings
from aleph_client.commands.utils import setup_logging
from aleph_client.utils import AsyncTyper

logger = logging.getLogger(__name__)
app = AsyncTyper(no_args_is_help=True)


@app.command(name="list")
async def list_ports(
    address: Annotated[Optional[str], typer.Option(help=help_strings.TARGET_ADDRESS)] = None,
    item_hash: Annotated[Optional[str], typer.Option(help=help_strings.PORT_FORWARDER_ITEM_HASH)] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    chain: Annotated[Optional[Chain], typer.Option(help=help_strings.ADDRESS_CHAIN)] = None,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
):
    """List all port forwards for a given address and/or specific item hash"""

    setup_logging(debug)

    account = _load_account(private_key, private_key_file, chain=chain)
    address = address or settings.ADDRESS_TO_USE or account.get_address()

    async with AlephHttpClient(api_server=settings.API_HOST) as client:
        # Get all port forwards for the address
        try:
            typer.echo(f"Getting port forwards for address: {address}")
            ports_config = await client.port_forwarder.get_address_ports(address=address)

            # Debug logging
            if debug:
                typer.echo(f"Debug - Port config received: {ports_config}")

            if not ports_config.data:
                typer.echo(f"No port forwards found for address: {address}")
                return

            # Create a table to display the port forwards
            table = Table(box=box.HEAVY_EDGE, style="cyan", title="Port Forwards", title_style="bold white on blue")
            table.add_column("Item Hash", style="bright_blue")
            table.add_column("Name", style="bright_blue")
            table.add_column("Port", style="bright_green")
            table.add_column("TCP", style="bright_yellow")
            table.add_column("UDP", style="bright_magenta")

            console = Console()

            # Process the data for display
            for config in ports_config.data:
                ports_map = config.root

                for ih, ports in ports_map.items():
                    name = await client.instance.get_name_of_executable(item_hash=ItemHash(ih))

                    # If an item hash is specified, only show that one
                    if item_hash and ih != item_hash:
                        continue

                    for port_num, flags in ports.ports.items():
                        tcp_check = "+" if flags.tcp else "-"
                        udp_check = "+" if flags.udp else "-"

                        # Create stylized display for hash and name
                        item_hash_display = f"[bright_cyan]{ih}[/bright_cyan]"
                        name_display = f"[bold bright_white on blue]{name}[/bold bright_white on blue]" if name else ""

                        # Format port display
                        port_display = f"[bold]{port_num}[/bold]"

                        table.add_row(item_hash_display, name_display, port_display, tcp_check, udp_check)

            if table.row_count == 0:
                if item_hash:
                    typer.echo(f"No port forwards found for item hash: {item_hash}")
                else:
                    typer.echo(f"No port forwards found for address: {address}")
                return

            console.print(table)

            # Print info panel with enhanced styling
            info = Text()
            info.append(Text.from_markup(f"[bold]Address:[/bold] [bright_green]{address}[/bright_green]"))

            if item_hash:
                info.append("\n")
                info.append(Text.from_markup(f"[bold]Item Hash:[/bold] [bright_magenta]{item_hash}[/bright_magenta]"))

            console.print(
                Panel(
                    info,
                    title="[bold]Port Forward Info[/bold]",
                    border_style="bright_cyan",
                    expand=False,
                    padding=(1, 2),
                    title_align="center",
                    box=box.DOUBLE,
                )
            )
        except ClientResponseError as e:
            if e.status == 404:
                typer.echo(f"No port forwards found for address: {address}")
                return
            else:
                typer.echo(f"Error: {e}")
                raise typer.Exit(code=1) from e
        except Exception as e:
            typer.echo(f"An error occurred: {e}")
            raise typer.Exit(code=1) from e


@app.command()
async def create(
    item_hash: Annotated[str, typer.Argument(help=help_strings.PORT_FORWARDER_ITEM_HASH)],
    port: Annotated[int, typer.Argument(help=help_strings.PORT_FORWARDER_PORT)],
    tcp: Annotated[bool, typer.Option(help=help_strings.PORT_FORWARDER_TCP)] = True,
    udp: Annotated[bool, typer.Option(help=help_strings.PORT_FORWARDER_UDP)] = False,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    chain: Annotated[Optional[Chain], typer.Option(help=help_strings.ADDRESS_CHAIN)] = None,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
):
    """Create a new port forward for a specific item hash"""

    setup_logging(debug)

    if not (tcp or udp):
        typer.echo("Error: At least one of TCP or UDP must be enabled")
        raise typer.Exit(code=1)

    if port < 1 or port > 65535:
        typer.echo("Error: Port must be between 1 and 65535")
        raise typer.Exit(code=1)

    account = _load_account(private_key, private_key_file, chain=chain)

    # Create the port flags
    port_flags = PortFlags(tcp=tcp, udp=udp)

    # Create the ports configuration
    ports = Ports(ports={port: port_flags})

    try:
        async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
            try:
                message, status = await client.port_forwarder.create_ports(item_hash=ItemHash(item_hash), ports=ports)
                typer.echo(f"Currents status: {status}")
                typer.echo(f"Port forward created successfully for {item_hash} on port {port}")
                typer.echo(f"TCP: {'Enabled' if tcp else 'Disabled'}, UDP: {'Enabled' if udp else 'Disabled'}")
            except MessageNotProcessed as e:
                typer.echo(f"Error: Item hash {item_hash} message not processed. Status: {e.status}")
                raise typer.Exit(code=1) from e
            except NotAuthorize as e:
                typer.echo(f"Error: Not authorized to create port forward for {item_hash}")
                typer.echo(f"Target address: {e.target_address}, Your address: {e.current_address}")
                raise typer.Exit(code=1) from e

    except Exception as e:
        typer.echo(f"An error occurred: {e}")
        raise typer.Exit(code=1) from e


@app.command()
async def update(
    item_hash: Annotated[str, typer.Argument(help=help_strings.PORT_FORWARDER_ITEM_HASH)],
    port: Annotated[int, typer.Argument(help=help_strings.PORT_FORWARDER_PORT)],
    tcp: Annotated[bool, typer.Option(help=help_strings.PORT_FORWARDER_TCP)] = True,
    udp: Annotated[bool, typer.Option(help=help_strings.PORT_FORWARDER_UDP)] = False,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    chain: Annotated[Optional[Chain], typer.Option(help=help_strings.ADDRESS_CHAIN)] = None,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
):
    """Update an existing port forward for a specific item hash"""

    setup_logging(debug)

    if not (tcp or udp):
        typer.echo("Error: At least one of TCP or UDP must be enabled")
        raise typer.Exit(code=1)

    if port < 1 or port > 65535:
        typer.echo("Error: Port must be between 1 and 65535")
        raise typer.Exit(code=1)

    account = _load_account(private_key, private_key_file, chain=chain)

    # First check if the port forward exists
    async with AlephHttpClient(api_server=settings.API_HOST) as client:
        try:
            existing_config = await client.port_forwarder.get_ports(
                address=account.get_address(), item_hash=ItemHash(item_hash)
            )

            if not existing_config or port not in existing_config.ports:
                typer.echo(
                    f"Port forward for {item_hash} on port {port} does not exist. Use 'create' to create a new one."
                )
                raise typer.Exit(code=1)
        except ClientResponseError as e:
            if e.status == 404:
                typer.echo(
                    f"No port forwards found for address: {account.get_address()}. Use 'create' to create a new one."
                )
                raise typer.Exit(code=1) from e
            else:
                typer.echo(f"Error: {e}")
                raise typer.Exit(code=1) from e

    # Create the port flags
    port_flags = PortFlags(tcp=tcp, udp=udp)

    # Create the updated ports configuration
    updated_ports = Ports(ports={})
    for p, flags in existing_config.ports.items():
        if p == port:
            updated_ports.ports[p] = port_flags
        else:
            updated_ports.ports[p] = flags

    try:
        async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
            try:
                message, status = await client.port_forwarder.update_ports(
                    item_hash=ItemHash(item_hash), ports=updated_ports
                )

                if status == MessageStatus.PROCESSED:
                    typer.echo(f"Port forward updated successfully for {item_hash} on port {port}")
                    typer.echo(f"TCP: {'Enabled' if tcp else 'Disabled'}, UDP: {'Enabled' if udp else 'Disabled'}")
                else:
                    typer.echo(f"Port forward update request was accepted but not yet processed. Status: {status}")

            except MessageNotProcessed as e:
                typer.echo(f"Error: Item hash {item_hash} message not processed. Status: {e.status}")
                raise typer.Exit(code=1) from e
            except NotAuthorize as e:
                typer.echo(f"Error: Not authorized to update port forward for {item_hash}")
                typer.echo(f"Target address: {e.target_address}, Your address: {e.current_address}")
                raise typer.Exit(code=1) from e

    except Exception as e:
        typer.echo(f"An error occurred: {e}")
        raise typer.Exit(code=1) from e


@app.command()
async def delete(
    item_hash: Annotated[str, typer.Argument(help=help_strings.PORT_FORWARDER_ITEM_HASH)],
    port: Annotated[Optional[int], typer.Option(help=help_strings.PORT_FORWARDER_PORT)] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    chain: Annotated[Optional[Chain], typer.Option(help=help_strings.ADDRESS_CHAIN)] = None,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
):
    """Delete a port forward for a specific item hash, or all port forwards if no port is specified"""

    setup_logging(debug)

    if port and (port < 1 or port > 65535):
        typer.echo("Error: Port must be between 1 and 65535")
        raise typer.Exit(code=1)

    account = _load_account(private_key, private_key_file, chain=chain)

    # First check if the port forward exists
    async with AlephHttpClient(api_server=settings.API_HOST) as client:
        try:
            existing_config = await client.port_forwarder.get_ports(
                address=account.get_address(), item_hash=ItemHash(item_hash)
            )

            if not existing_config or not existing_config.ports:
                typer.echo(f"No port forwards found for {item_hash}")
                raise typer.Exit(code=1)

            if port and port not in existing_config.ports:
                typer.echo(f"Port forward for {item_hash} on port {port} does not exist")
                raise typer.Exit(code=1)
        except ClientResponseError as e:
            if e.status == 404:
                typer.echo(f"No port forwards found for address: {account.get_address()}")
                raise typer.Exit(code=1) from e
            else:
                typer.echo(f"Error: {e}")
                raise typer.Exit(code=1) from e

    try:
        async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_HOST) as client:
            try:
                if port:
                    updated_ports = Ports(ports={})
                    for p, flags in existing_config.ports.items():
                        if p != port:
                            updated_ports.ports[p] = flags

                    if not updated_ports.ports:
                        message, status = await client.port_forwarder.delete_ports(item_hash=ItemHash(item_hash))
                    else:
                        message, status = await client.port_forwarder.update_ports(
                            item_hash=ItemHash(item_hash), ports=updated_ports
                        )

                    if status == MessageStatus.PROCESSED:
                        typer.echo(f"Port forward deleted successfully for {item_hash} on port {port}")
                    else:
                        typer.echo(f"Port forward delete request was accepted but not yet processed. Status: {status}")

                else:
                    # Delete all port forwards for the item hash
                    message, status = await client.port_forwarder.delete_ports(item_hash=ItemHash(item_hash))

                    if status == MessageStatus.PROCESSED:
                        typer.echo(f"All port forwards deleted successfully for {item_hash}")
                    else:
                        typer.echo(f"Port forwards delete request was accepted but not yet processed. Status: {status}")

            except MessageNotProcessed as e:
                typer.echo(f"Error: Item hash {item_hash} message not processed. Status: {e.status}")
                raise typer.Exit(code=1) from e
            except NotAuthorize as e:
                typer.echo(f"Error: Not authorized to delete port forward for {item_hash}")
                typer.echo(f"Target address: {e.target_address}, Your address: {e.current_address}")
                raise typer.Exit(code=1) from e

    except Exception as e:
        typer.echo(f"An error occurred: {e}")
        raise typer.Exit(code=1) from e


@app.command(name="refresh")
async def refresh(
    item_hash: Annotated[str, typer.Argument(help=help_strings.PORT_FORWARDER_ITEM_HASH)],
    chain: Annotated[Optional[Chain], typer.Option(help=help_strings.ADDRESS_CHAIN)] = None,
    private_key: Annotated[Optional[str], typer.Option(help=help_strings.PRIVATE_KEY)] = settings.PRIVATE_KEY_STRING,
    private_key_file: Annotated[
        Optional[Path], typer.Option(help=help_strings.PRIVATE_KEY_FILE)
    ] = settings.PRIVATE_KEY_FILE,
    debug: Annotated[bool, typer.Option(help="Enable debug logging")] = False,
):
    """
    Ask a CRN to fetch the latest port configurations from sender aggregates.
    """

    setup_logging(debug)

    account = _load_account(private_key, private_key_file, chain=chain)

    try:
        async with AuthenticatedAlephHttpClient(api_server=settings.API_HOST, account=account) as client:
            instance: InstanceMessage = await client.get_message(item_hash=item_hash, message_type=InstanceMessage)
            crn_list = await client.crn.get_crns_list()
            _, allocation = await client.instance.get_instance_allocation_info(instance, crn_list)

            if not allocation:
                typer.echo("No allocation Found")
                typer.Exit(1)

            crn_url = allocation.crn_url if isinstance(allocation, InstanceManual) else allocation.allocations.node.url

            result = await client.crn.update_instance_config(crn_address=crn_url, item_hash=item_hash)
            typer.echo(result)
    except Exception as e:
        typer.echo(f"An error occurred: {e}")
        raise typer.Exit(code=1) from e
