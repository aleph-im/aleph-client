import logging
import os
import sys
import re
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union
import aiohttp
import asyncio

import typer
from aleph.sdk.types import GenericMessage
from pygments import highlight
from pygments.formatters.terminal256 import Terminal256Formatter
from pygments.lexers import JsonLexer
from rich.prompt import IntPrompt, Prompt, PromptError
from rich.live import Live
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from typer import echo

def colorful_json(obj: str):
    """Render a JSON string with colors."""
    return highlight(
        obj,
        lexer=JsonLexer(),
        formatter=Terminal256Formatter(),
    )


def colorful_message_json(message: GenericMessage):
    """Render a message in JSON with colors."""
    return colorful_json(message.json(sort_keys=True, indent=4))


def input_multiline() -> str:
    """Prompt the user for a multiline input."""
    echo("Enter/Paste your content. Ctrl-D or Ctrl-Z ( windows ) to save it.")
    contents = ""
    while True:
        try:
            line = input()
        except EOFError:
            break
        contents += line + "\n"
    return contents


def setup_logging(debug: bool = False):
    level = logging.DEBUG if debug else logging.WARNING
    logging.basicConfig(level=level)


def yes_no_input(text: str, default: bool) -> bool:
    return Prompt.ask(text, choices=["y", "n"], default=default) == "y"


def prompt_for_volumes():
    while yes_no_input("Add volume ?", default=False):
        mount = Prompt.ask("Mount path: ")
        comment = Prompt.ask("Comment: ")
        persistent = yes_no_input("Persist on VM host?", default=False)
        if persistent:
            name = Prompt.ask("Name: ")
            size_mib = validated_int_prompt("Size (MiB): ", min_value=1)
            yield {
                "comment": comment,
                "mount": mount,
                "name": name,
                "persistence": "host",
                "size_mib": size_mib,
            }
        else:
            ref = Prompt.ask("Item hash: ")
            use_latest = yes_no_input("Use latest version ?", default=True)
            yield {
                "comment": comment,
                "mount": mount,
                "ref": ref,
                "use_latest": use_latest,
            }


def volume_to_dict(volume: List[str]) -> Optional[Dict[str, Union[str, int]]]:
    if not volume:
        return None
    dict_store: Dict[str, Union[str, int]] = {}
    for word in volume:
        split_values = word.split(",")
        for param in split_values:
            p = param.split("=")
            if p[1].isdigit():
                dict_store[p[0]] = int(p[1])
            elif p[1] in ["True", "true", "False", "false"]:
                dict_store[p[0]] = bool(p[1].capitalize())
            else:
                dict_store[p[0]] = p[1]

    return dict_store


def get_or_prompt_volumes(ephemeral_volume, immutable_volume, persistent_volume):
    volumes = []
    # Check if the volumes are empty
    if (
        persistent_volume is None
        or ephemeral_volume is None
        or immutable_volume is None
    ):
        for volume in prompt_for_volumes():
            volumes.append(volume)
            typer.echo("\n")

    # else parse all the volumes that have passed as the cli parameters and put it into volume list
    else:
        if len(persistent_volume) > 0:
            persistent_volume_dict = volume_to_dict(volume=persistent_volume)
            volumes.append(persistent_volume_dict)
        if len(ephemeral_volume) > 0:
            ephemeral_volume_dict = volume_to_dict(volume=ephemeral_volume)
            volumes.append(ephemeral_volume_dict)
        if len(immutable_volume) > 0:
            immutable_volume_dict = volume_to_dict(volume=immutable_volume)
            volumes.append(immutable_volume_dict)
    return volumes


def str_to_datetime(date: Optional[str]) -> Optional[datetime]:
    """
    Converts a string representation of a date/time to a datetime object.

    The function can accept either a timestamp or an ISO format datetime string as the input.
    """
    if date is None:
        return None
    try:
        date_f = float(date)
        return datetime.fromtimestamp(date_f)
    except ValueError:
        pass
    return datetime.fromisoformat(date)


T = TypeVar("T")


def validated_prompt(
    prompt: str,
    validator: Callable[[str], Any],
    default: Optional[str] = None,
) -> str:
    while True:
        try:
            value = Prompt.ask(
                prompt,
                default=default,
            )
        except PromptError:
            echo(f"Invalid input: {value}\nTry again.")
            continue
        if value is None and default is not None:
            return default
        if validator(str(value)):
            return str(value)
        echo(f"Invalid input: {value}\nTry again.")


def validated_int_prompt(
    prompt: str,
    default: Optional[int] = None,
    min_value: Optional[int] = None,
    max_value: Optional[int] = None,
) -> int:
    while True:
        try:
            value = IntPrompt.ask(
                prompt + f" [min: {min_value or '-'}, max: {max_value or '-'}]",
                default=default,
            )
        except PromptError:
            echo(f"Invalid input: {value}\nTry again.")
            continue
        if value is None:
            if default is not None:
                return default
            else:
                value = 0
        if min_value is not None and value < min_value:
            echo(f"Invalid input: {value}\nTry again.")
            continue
        if max_value is not None and value > max_value:
            echo(f"Invalid input: {value}\nTry again.")
            continue
        return value


def is_environment_interactive() -> bool:
    """
    Check if the current environment is interactive and can answer questions.
    """
    return all(
        (
            sys.stdin.isatty(),
            sys.stdout.isatty(),
            not os.environ.get("CI", False),
            not os.environ.get("DEBIAN_NONINTERACTIVE") == "noninteractive",
        )
    )


from aleph_client.commands.node import NodeInfo, _fetch_nodes, _escape_and_normalize, _remove_ansi_escape, _format_score, _format_status


class ProgressTable:
    def __init__(self, progress, table):
        self.progress = progress
        self.table = table

    def __rich_console__(self, console, options):
        yield self.progress
        yield self.table


logger = logging.getLogger(__name__)


async def fetch_crn_info():
    node_info = await _fetch_nodes()
    table = Table(title="Compute Node Information")
    table.add_column("Score", style="green", no_wrap=True, justify="center")
    table.add_column("Name", style="#029AFF", justify="left")
    table.add_column("CPU", style="green", justify="left")
    table.add_column("RAM", style="green", justify="left")
    table.add_column("HDD", style="green", justify="left")
    table.add_column("Version", style="green", justify="left")
    table.add_column("Reward Address", style="green", justify="center")
    table.add_column("Address", style="green", justify="center")

    console = Console()
    progress = Progress()
    task = progress.add_task("[green]Fetching node info... It might take some time", total=len(node_info.nodes))

    progress_table = ProgressTable(progress, table)
    item_hashes = []

    async with aiohttp.ClientSession() as session:
        with Live(progress_table, console=console, refresh_per_second=2):
            tasks = [fetch_and_update_table(session, node, table, progress, task, item_hashes) for node in node_info.nodes]
            await asyncio.gather(*tasks)

    console.print(table)
    return item_hashes


async def fetch_and_update_table(session: aiohttp.ClientSession, node: NodeInfo, table: Table, progress: ProgressTable, task: list, item_hashes: list):
    try:
        system_info, version = await asyncio.gather(
            fetch_crn_system(session, node),
            get_crn_version(session, node)
        )
        async with session.get(node["address"] + "status/check/ipv6") as resp:
            if resp.status == 200:
                node_stream = node["stream_reward"]
                if node_stream and system_info:
                    node_name = _escape_and_normalize(node["name"])
                    node_name = _remove_ansi_escape(node_name)
                    node_address = node["address"]
                    score = _format_score(node["score"])
                    cpu = f"{system_info['cpu']['count']} {system_info['properties']['cpu']['architecture']}"
                    hdd = f"{system_info['disk']['available_kB'] / 1024 / 1024:.2f} GB"
                    ram = f"{system_info['mem']['available_kB'] / 1024 / 1024:.2f} GB"
                    table.add_row(score, node_name, cpu, ram, hdd, version, node_stream, node_address)
                    item_hashes.append(node_stream)
    except Exception as e:
        pass
    finally:
        progress.update(task, advance=1)


async def fetch_crn_system(session: aiohttp.ClientSession, node: NodeInfo):
    try:
        async with session.get(node["address"] + "about/usage/system") as resp:
            if resp.status == 200:
                data = await resp.json()
    except Exception as e:
        data = None
    return data

async def get_crn_version(session: aiohttp.ClientSession, node: NodeInfo):
    try:
        async with session.get(node['address']) as resp:
            if resp.status == 200:
                data = await resp.text()
                match = re.search(r"const NODE_VERSION = '([^']+)';", data)
                if match:
                    version = match.group(1)
    except Exception as e:
        version = None
    return version