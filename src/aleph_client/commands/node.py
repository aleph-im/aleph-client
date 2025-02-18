from __future__ import annotations

import datetime
import json as json_lib
import logging
import re
import unicodedata
from typing import Annotated, Optional

import aiohttp
import typer
from aleph.sdk.conf import settings
from rich import text
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from aleph_client.commands.utils import setup_logging
from aleph_client.utils import AsyncTyper, sanitize_url

logger = logging.getLogger(__name__)
app = AsyncTyper(no_args_is_help=True)

node_link = (
    f"{sanitize_url(settings.API_HOST)}/api/v0/aggregates/0xa1B3bb7d2332383D96b7796B908fB7f7F3c2Be10.json?"
    "keys=corechannel"
)


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
    table.add_column("URL", style="orchid", justify="center")

    for node in node_info.nodes:
        # Prevent escaping with name
        node_name = node["name"]
        node_name = _escape_and_normalize(node_name)
        node_name = _remove_ansi_escape(node_name)
        node_hash = node["hash"]

        #  Format Value
        creation_time = datetime.datetime.fromtimestamp(node["time"], tz=datetime.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        score = _format_score(node["score"])
        decentralization = _format_score(node["decentralization"])
        status = _format_status(node["status"])
        node_url = node["address"]
        table.add_row(
            score,
            node_name,
            creation_time,
            decentralization,
            status,
            node_hash,
            node_url,
        )

    console = Console()
    console.print(table)


def _filter_node(
    active: bool,
    address: Optional[str],
    core_info,
    payg_receiver=Optional[str],
    crn_url=Optional[str],
    crn_hash=Optional[str],
    ccn_hash=Optional[str],
):
    result = []
    try:
        node_url = not crn_url or sanitize_url(crn_url)
    except Exception as e:
        logger.debug(e)
    for node in core_info:
        try:
            if "total_staked" in node:  # CCN
                if (
                    (not active or (node["status"] == "active" and node["score"] > 0))
                    and (not address or node["owner"] == address)
                    and (not ccn_hash or node["hash"] == ccn_hash)
                ):
                    result.append(node)
            elif "parent" in node:  # CRN
                sanitized_url = "address" in node and sanitize_url(node["address"])
                if sanitized_url:
                    node["address"] = sanitized_url
                if (
                    (not active or (node["status"] == "linked" and node["score"] > 0))
                    and (not address or node["owner"] == address)
                    and (not payg_receiver or node["stream_reward"] == payg_receiver)
                    and (not crn_url or node["address"] == node_url)
                    and (not crn_hash or node["hash"] == crn_hash)
                    and (not ccn_hash or node["parent"] == ccn_hash)
                ):
                    result.append(node)
        except Exception as e:
            logger.debug(e)
    return result


def _show_core(node_info):
    table = Table(title="Core Channel Node Information")
    table.add_column("Score", style="green", no_wrap=True, justify="right")
    table.add_column("Name", style="#029AFF", justify="left")
    table.add_column("Staked", style="#029AFF", justify="left")
    table.add_column("Linked", style="#029AFF", justify="left")
    table.add_column("Creation Time", style="#029AFF", justify="center")
    table.add_column("Status", style="green", justify="right")
    table.add_column("Item Hash", style="green", justify="center")

    for node in node_info:
        # Prevent escaping with name
        node_name = node["name"]
        node_name = _escape_and_normalize(node_name)
        node_name = _remove_ansi_escape(node_name)
        node_hash = node["hash"]

        # Format Value
        creation_time = datetime.datetime.fromtimestamp(node["time"], tz=datetime.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        score = _format_score(node["score"])
        status = _format_status(node["status"])

        table.add_row(
            score,
            node_name,
            f"{int(node['total_staked']):,}",
            str(len(node["resource_nodes"])),
            creation_time,
            status,
            node_hash,
        )

    console = Console()
    console.print(table)


@app.command()
async def compute(
    json: Annotated[bool, typer.Option(help="Print as json instead of rich table")] = False,
    active: Annotated[bool, typer.Option(help="Only show active nodes")] = False,
    address: Annotated[Optional[str], typer.Option(help="Owner address to filter by")] = None,
    payg_receiver: Annotated[
        Optional[str], typer.Option(help="PAYG (Pay-As-You-Go) receiver address to filter by")
    ] = None,
    crn_url: Annotated[Optional[str], typer.Option(help="CRN URL to filter by")] = None,
    crn_hash: Annotated[Optional[str], typer.Option(help="CRN hash to filter by")] = None,
    ccn_hash: Annotated[Optional[str], typer.Option(help="CCN hash to filter by")] = None,
    debug: Annotated[bool, typer.Option()] = False,
):
    """Get all compute node (CRN) on aleph network"""

    setup_logging(debug)

    compute_info: NodeInfo = await _fetch_nodes()
    compute_info.nodes = _filter_node(
        core_info=compute_info.nodes,
        active=active,
        address=address,
        payg_receiver=payg_receiver,
        crn_url=crn_url,
        crn_hash=crn_hash,
        ccn_hash=ccn_hash,
    )

    if not json:
        _show_compute(compute_info)
    else:
        typer.echo(json_lib.dumps(compute_info.nodes, indent=4))


@app.command()
async def core(
    json: Annotated[bool, typer.Option(help="Print as json instead of rich table")] = False,
    active: Annotated[bool, typer.Option(help="Only show active nodes")] = False,
    address: Annotated[Optional[str], typer.Option(help="Owner address to filter by")] = None,
    ccn_hash: Annotated[Optional[str], typer.Option(help="CCN hash to filter by")] = None,
    debug: Annotated[bool, typer.Option()] = False,
):
    """Get all core node (CCN) on aleph"""
    setup_logging(debug)

    core_info: NodeInfo = await _fetch_nodes()
    core_info.core_node = _filter_node(core_info=core_info.core_node, active=active, address=address, ccn_hash=ccn_hash)

    if not json:
        _show_core(node_info=core_info.core_node)
    else:
        typer.echo(json_lib.dumps(core_info.core_node, indent=4))
