import logging
import os
from random import random
import sys
import re
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Text, TypeVar, Union, Tuple
import aiohttp
import asyncio

import aiohttp.client_exceptions
import async_timeout
import typer
from aleph.sdk.types import GenericMessage
from pygments import highlight
from pygments.formatters.terminal256 import Terminal256Formatter
from pygments.lexers import JsonLexer
from rich.prompt import IntPrompt, Prompt, PromptError
from rich.live import Live
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, TaskID
from typer import echo
from aleph_client.conf import settings
from aleph_message.models.execution.environment import CpuProperties
from pydantic import BaseModel
import psutil

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

logger = logging.getLogger(__name__)


from aleph_client.commands.node import NodeInfo, _fetch_nodes, _escape_and_normalize, _remove_ansi_escape, _format_score

# Local variable to tell the end of queue process

# Class to regroup both progress bar and the table for cleaner code
class ProgressTable:
    def __init__(self, progress, table):
        self.progress = progress
        self.table = table

    def __rich_console__(self, console, options):
        yield self.progress
        yield self.table

# This is a copy from aleph-vm
class LoadAverage(BaseModel):
    load1: float
    load5: float
    load15: float

    @classmethod
    def from_psutil(cls, psutil_loadavg: Tuple[float, float, float]):
        return cls(
            load1=psutil_loadavg[0],
            load5=psutil_loadavg[1],
            load15=psutil_loadavg[2],
        )
    
class CoreFrequencies(BaseModel):
    min: float
    max: float

    @classmethod
    def from_psutil(cls, psutil_freq: psutil._common.scpufreq):
        min_ = psutil_freq.min or psutil_freq.current
        max_ = psutil_freq.max or psutil_freq.current
        return cls(min=min_, max=max_)

class CpuUsage(BaseModel):
    count: int
    load_average: LoadAverage
    core_frequencies: CoreFrequencies


class MemoryUsage(BaseModel):
    total_kB: int
    available_kB: int


class DiskUsage(BaseModel):
    total_kB: int
    available_kB: int


class UsagePeriod(BaseModel):
    start_timestamp: datetime
    duration_seconds: float


class MachineProperties(BaseModel):
    cpu: CpuProperties


class MachineUsage(BaseModel):
    cpu: CpuUsage
    mem: MemoryUsage
    disk: DiskUsage
    period: UsagePeriod
    properties: MachineProperties
    active: bool = True


class MachineInfo(BaseModel):
    system_info: MachineUsage
    score: str
    name: str
    version: str
    reward_address: str
    address: str


# Sentinel value to indicate end of queue processing
END_OF_QUEUE = None


async def fetch_crn_info() -> list:
    """
    Fetches compute node information asynchronously.
    Display and update a Live tab where CRN info will be displayed

    Returns:
        list: List of item hashes.
    """
    node_info: NodeInfo = await _fetch_nodes()
    table = Table(title="Compute Node Information")
    table.add_column("Score", style="green", no_wrap=True, justify="center")
    table.add_column("Name", style="#029AFF", justify="left")
    table.add_column("CPU", style="green", justify="left")
    table.add_column("RAM", style="green", justify="left")
    table.add_column("HDD", style="green", justify="left")
    table.add_column("Version", style="green", justify="center")
    table.add_column("Reward Address", style="green", justify="center")
    table.add_column("Address", style="green", justify="center")

    console = Console()
    progress = Progress()
    task = progress.add_task("[green]Fetching node info... It might take some time", total=len(node_info.nodes))

    progress_table = ProgressTable(progress, table)
    item_hashes: list = []

    queue: asyncio.Queue[Optional[MachineInfo]]= asyncio.Queue()

    async with aiohttp.ClientSession() as session:
        with Live(progress_table, console=console, refresh_per_second=2):
            fetch_task = asyncio.create_task(fetch_data(session, node_info, queue, progress, task, item_hashes))
            update_task = asyncio.create_task(update_table(queue, table))
            await asyncio.gather(fetch_task, update_task)

    return item_hashes


async def fetch_data(session: aiohttp.ClientSession, node_info: NodeInfo, queue: asyncio.Queue[Optional[MachineInfo]], progress: Progress, task: TaskID, item_hashes: list):
    """
    Fetches data for each node in node_info and queues MachineInfo objects to the queue.

    Args:
        session (aiohttp.ClientSession): Aiohttp client session.
        node_info (NodeInfo): Node information.
        queue (asyncio.Queue[Optional[MachineInfo]]): Asyncio queue to store MachineInfo objects.
        progress (Progress): Rich Progress object.
        task (TaskID): Rich TaskID object.
        item_hashes (list): List to store item hashes.
    """
    
    tasks = [fetch_and_queue(session, node, queue, progress, task, item_hashes) for node in node_info.nodes]
    await asyncio.gather(*tasks)
    await queue.put(END_OF_QUEUE)


async def enqueue_machine_usage_info(node : dict, system_info: Optional[MachineUsage], queue: asyncio.Queue[Optional[MachineInfo]], version: str, item_hashes: list):
    """
    Creates MachineInfo object which will store CRN information and puts it into the queue.

    Args:
        node (dict): Node information dictionary.
        system_info (Optional[MachineUsage]): Machine usage information.
        queue (asyncio.Queue[Optional[MachineInfo]]): Asyncio queue to store MachineInfo objects.
        version (str): Version of the node.
        item_hashes (list): List to store item hashes.
    """
    
    node_reward: str = node["stream_reward"]

    if node_reward and system_info:
        node_name = _escape_and_normalize(node["name"])
        node_name = _remove_ansi_escape(node_name)
        node_address: str = node["address"]
        score = _format_score(node["score"])
        
        machine_info = MachineInfo(
            system_info=system_info,
            score=str(score),
            name=node_name,
            version=version,
            reward_address=node_reward,
            address=node_address
        )

        await queue.put(machine_info)
        item_hashes.append(node_reward)


async def fetch_and_queue(session: aiohttp.ClientSession, node: dict, queue: asyncio.Queue[Optional[MachineInfo]], progress: Progress, task: TaskID, item_hashes: list):
    """
    Fetches data from the node and send it to 'enqueue_machine_usage_info()' which will queues MachineInfo object.

    Args:
        session (aiohttp.ClientSession): Aiohttp client session.
        node (dict): Node information dictionary.
        queue (asyncio.Queue[Optional[MachineInfo]]): Asyncio queue to store MachineInfo objects.
        progress (Progress): Rich Progress object.
        task (TaskID): Rich TaskID object.
        item_hashes (list): List to store item hashes.
    """
    
    url: str = node["address"].rstrip('/') + '/status/check/ipv6'

    try:
        system_info, version = await asyncio.gather(
            fetch_crn_system(session, node),
            get_crn_version(session, node)
        )
        async with async_timeout.timeout(settings.HTTP_REQUEST_TIMEOUT + settings.HTTP_REQUEST_TIMEOUT * 0.3 * random()):
            async with session.get(url) as resp:
                resp.raise_for_status()
                await enqueue_machine_usage_info(node, system_info, queue, version, item_hashes)
    except TimeoutError:
        logger.debug(f'Timeout while fetching: {url}')
    except aiohttp.client_exceptions.ClientConnectionError:
        logger.debug(f'Error on connection: {url}')
    except Exception as e:
        logger.debug(f'This error occured: {e}')
    finally:
        progress.update(task, advance=1)


def convert_system_info_to_str(data: MachineInfo) -> Tuple[str, str, str]:
    """
    Converts MachineInfo object that contains CPU, RAM and HDD information to a tupple of strings.

    Args:
        data (MachineInfo): MachineInfo object.

    Returns:
        Tuple[str, str, str]: CPU, RAM, and HDD information.
    """

    cpu = f"{data.system_info.cpu.count} {data.system_info.properties.cpu.architecture}"
    hdd = f"{data.system_info.disk.available_kB / 1024 / 1024:.2f} GB"
    ram = f"{data.system_info.mem.available_kB / 1024 / 1024:.2f} GB"

    return cpu, hdd, ram


async def update_table(queue: asyncio.Queue[Optional[MachineInfo]], table: Table):
    """
    Updates table with MachineInfo objects from the queue.

    Args:
        queue (asyncio.Queue[Optional[MachineInfo]]): Asyncio queue to store MachineInfo objects.
        table (Table): Rich Table object.
    """
    
    while True:
        data: Optional[MachineInfo] = await queue.get()
        if data is END_OF_QUEUE:
            break

        cpu, hdd, ram = convert_system_info_to_str(data)
        table.add_row(data.score, data.name, cpu, ram, hdd, data.version, data.reward_address, data.address)


async def fetch_crn_system(session: aiohttp.ClientSession, node: dict) -> Optional[MachineUsage]:
    """
    Fetches compute node system information asynchronously.

    Args:
        session (aiohttp.ClientSession): Aiohttp client session.
        node (dict): Node information dictionary.

    Returns:
        Optional[MachineUsage]: Machine usage information.
    """
    
    data = None

    try:
        async with async_timeout.timeout(settings.HTTP_REQUEST_TIMEOUT + settings.HTTP_REQUEST_TIMEOUT * 0.3 * random()):
            url: str = node["address"].rstrip('/') + '/about/usage/system'
            async with session.get(url) as resp:
                resp.raise_for_status()
                data_raw = await resp.json()
                data = MachineUsage.parse_obj(data_raw)
    except TimeoutError:
        logger.debug(f'Timeout while fetching: {url}')
    except aiohttp.client_exceptions.ClientConnectionError:
        logger.debug(f'Error on connection: {url}')
    except Exception as e:
        logger.debug(f'This error occured: {e}')
    return data


async def get_crn_version(session: aiohttp.ClientSession, node: dict) -> str:
    """
    Fetches compute node version asynchronously.

    Args:
        session (aiohttp.ClientSession): Aiohttp client session.
        node (dict): Node information dictionary.

    Returns:
        str: Node version.
    """
    
    url = node["address"]
    version = "Can't fetch the version"

    try:
        async with async_timeout.timeout(3 * settings.HTTP_REQUEST_TIMEOUT + 3 * settings.HTTP_REQUEST_TIMEOUT * 0.3 * random()):
            async with session.get(url) as resp:
                resp.raise_for_status()
                if "Server" in resp.headers:
                    for server in resp.headers.getall("Server"):
                        version_match = re.findall(r"^aleph-vm/(.*)$", server)
                        if version_match and version_match[0]:
                            version = version_match[0]
    except (asyncio.TimeoutError):
        logger.debug(f'Timeout while fetching: {url}')
    except aiohttp.client_exceptions.ClientConnectionError:
        logger.debug(f'Error on connection: {url}')
    except Exception as e:
        logger.debug(f'This error occured: {e}')
    return version