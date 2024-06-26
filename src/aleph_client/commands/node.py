from __future__ import annotations

import datetime
import json as json_lib
import logging
import re
import unicodedata
from typing import Optional

import aiohttp
import typer
from rich import text
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from aleph_client.commands.utils import setup_logging
from aleph_client.utils import AsyncTyper

logger = logging.getLogger(__name__)
app = AsyncTyper(no_args_is_help=True)

node_link = "https://api2.aleph.im/api/v0/aggregates/0xa1B3bb7d2332383D96b7796B908fB7f7F3c2Be10.json?keys=corechannel"


class NodeInfo:
    def __init__(self, **kwargs):
        self.data = kwargs.get("data", {})
        self.nodes = self.data.get("corechannel", {}).get("resource_nodes", [])
        self.nodes.sort(key=lambda x: x.get("score", 0), reverse=True)
        self.core_node = self.data.get("corechannel", {}).get("nodes", [])
        self.core_node.sort(key=lambda x: x.get("score", 0), reverse=True)


async def _fetch_nodes() -> NodeInfo:
    """Fetch node aggregates and format it as NodeInfo"""
    async with aiohttp.ClientSession() as session:
        async with session.get(node_link) as resp:
            if resp.status != 200:
                logger.error("Unable to fetch node information")
                raise typer.Exit(1)

            data = await resp.json()
            return NodeInfo(**data)


def _escape_and_normalize(string: str) -> str:
    sanitized_text = escape(string)
    normalized_text = unicodedata.normalize("NFC", sanitized_text)
    return normalized_text


def _remove_ansi_escape(string: str) -> str:
    ansi_escape = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
    return ansi_escape.sub("", string)


def _format_score(score: float) -> text.Text:
    if score < 0.5:
        return text.Text(f"{score:.2%}", style="red", justify="right")
    elif score < 0.75:
        return text.Text(f"{score:.2%}", style="orange", justify="right")
    else:
        return text.Text(f"{score:.2%}", style="green", justify="right")


def _format_status(status):
    if status.lower() == "linked" or status.lower() == "active":
        return text.Text(status, style="green", justify="left")
    return text.Text(status, style="red", justify="left")


def _show_compute(node_info):
    table = Table(title="Compute Node Information")
    table.add_column("Score", style="green", no_wrap=True, justify="right")
    table.add_column("Name", style="#029AFF", justify="left")
    table.add_column("Creation Time", style="#029AFF", justify="center")
    table.add_column("Decentralization", style="green", justify="right")
    table.add_column("Status", style="green", justify="right")
    table.add_column("Item Hash", style="green", justify="center")

    for node in node_info.nodes:
        # Prevent escaping with name
        node_name = node["name"]
        node_name = _escape_and_normalize(node_name)
        node_name = _remove_ansi_escape(node_name)
        node_hash = node["hash"]

        #  Format Value
        creation_time = datetime.datetime.fromtimestamp(node["time"]).strftime("%Y-%m-%d %H:%M:%S")
        score = _format_score(node["score"])
        decentralization = _format_score(node["decentralization"])
        status = _format_status(node["status"])
        table.add_row(
            score,
            node_name,
            creation_time,
            decentralization,
            status,
            node_hash,
        )

    console = Console()
    console.print(table)


def _filter_node(active: bool, address: Optional[str], core_info):
    result = []
    for node in core_info:
        if active and node["status"] == "active" and node["score"] > 0:
            result.append(node)
        elif address and node["owner"] == address:
            result.append(node)
        elif not active and not address:
            result.append(node)
    return result


def _show_core(node_info):
    table = Table(title="Core Channel Node Information")
    table.add_column("Score", style="green", no_wrap=True, justify="right")
    table.add_column("Name", style="#029AFF", justify="left")
    table.add_column("Staked", style="#029AFF", justify="left")
    table.add_column("Linked", style="#029AFF", justify="left")
    table.add_column("Creation Time", style="#029AFF", justify="center")
    table.add_column("Status", style="green", justify="right")

    for node in node_info:
        # Prevent escaping with name
        node_name = node["name"]
        node_name = _escape_and_normalize(node_name)
        node_name = _remove_ansi_escape(node_name)

        # Format Value
        creation_time = datetime.datetime.fromtimestamp(node["time"]).strftime("%Y-%m-%d %H:%M:%S")
        score = _format_score(node["score"])
        status = _format_status(node["status"])

        table.add_row(
            score,
            node_name,
            f"{int(node['total_staked']):,}",
            str(len(node["resource_nodes"])),
            creation_time,
            status,
        )

    console = Console()
    console.print(table)


@app.command()
async def compute(
    json: bool = typer.Option(default=False, help="Print as json instead of rich table"),
    active: bool = typer.Option(default=False, help="Only show active nodes"),
    address: Optional[str] = typer.Option(default=None, help="Owner address to filter by"),
    debug: bool = False,
):
    """Get all compute node on aleph network"""

    setup_logging(debug)

    compute_info: NodeInfo = await _fetch_nodes()
    compute_info.nodes = _filter_node(core_info=compute_info.nodes, active=active, address=address)

    if not json:
        _show_compute(compute_info)
    else:
        typer.echo(json_lib.dumps(compute_info.nodes, indent=4))


@app.command()
async def core(
    json: bool = typer.Option(default=False, help="Print as json instead of rich table"),
    active: bool = typer.Option(default=False, help="Only show active nodes"),
    address: Optional[str] = typer.Option(default=None, help="Owner address to filter by"),
    debug: bool = False,
):
    """Get all core node on aleph"""
    setup_logging(debug)

    core_info: NodeInfo = await _fetch_nodes()
    core_info.core_node = _filter_node(core_info=core_info.core_node, active=active, address=address)

    if not json:
        _show_core(node_info=core_info.core_node)
    else:
        typer.echo(json_lib.dumps(core_info.core_node, indent=4))
