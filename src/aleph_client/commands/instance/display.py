from __future__ import annotations

import asyncio
import typing
from functools import partial
from typing import Callable, Literal, Set, Sized, Tuple, Union, cast

from aiohttp import InvalidURL
from pydantic import BaseModel
from rich.console import Console
from rich.live import Live
from rich.progress import Progress
from rich.table import Table

# from textual.containers import Center, Middle,
from textual.widgets import ProgressBar

from aleph_client.commands.instance.network import fetch_and_queue_crn_info, sanitize_url, fetch_crn_info
from aleph_client.commands.node import NodeInfo, _fetch_nodes, _format_score
from aleph_client.models import MachineInfo
from textual.widgets._data_table import CursorType

if typing.TYPE_CHECKING:
    from aleph_client.commands.instance.network import MachineInfoQueue


class ProgressTable:
    """Display a progress bar and a table side by side."""

    progress: Progress
    table: Table

    def __init__(self, progress, table):
        self.progress = progress
        self.table = table

    def __rich_console__(self, console: Console, options):
        yield self.progress
        yield self.table


def create_crn_resource_table() -> Table:
    """Prepare a table to display available resources on CRNs in order to schedule a PAYG instance on it."""
    table = Table(title="Compute Node Information")
    table.add_column("Score", style="green", no_wrap=True, justify="center")
    table.add_column("Name", style="#029AFF", justify="left")
    table.add_column("Cores", style="green", justify="left")
    table.add_column("RAM", style="green", justify="left")
    table.add_column("HDD", style="green", justify="left")
    table.add_column("Version", style="green", justify="center")
    table.add_column("Reward Address", style="green", justify="center")
    table.add_column("Address", style="green", justify="center")
    return table


def create_progress_bar(sized_object: Sized) -> Tuple[Progress, Callable[[], None]]:
    """Create a progress bar and a function to increment it.

    Args:
        sized_object: Sized object to create a progress bar for, typically a list.
    Returns:
        The progress bar and a function to increment it.
    """
    progress_bar = Progress()
    progress_bar_task = progress_bar.add_task(
        "[green]Fetching node info... It might take some time",
        total=len(sized_object),
    )
    # We use a partial function to create a function that increments the progress bar by 1
    # and can be called from within coroutines.
    increment_progress_bar: Callable[[], None] = partial(progress_bar.update, progress_bar_task, advance=1)
    return progress_bar, increment_progress_bar


def create_table_with_progress_bar(
    sized_object: Sized,
) -> Tuple[ProgressTable, Callable[[], None]]:
    """Create a table of CRNs together with a progress bar and a function to increment it.

    Args:
        sized_object: Sized object to create a progress bar for, typically a list.
    Returns:
        The table and the function to increment the progress bar.
    """
    progress_bar, increment_progress_bar = create_progress_bar(sized_object)
    table = create_crn_resource_table()
    return ProgressTable(progress_bar, table), increment_progress_bar


async def update_table(
    queue: MachineInfoQueue,
    table: DataTable,
    increment_progress_bar: Callable[[], None],
    valid_reward_addresses: Set[str],
) -> None:
    """
    Updates table with MachineInfo objects from the queue, updates progress bar and valid reward addresses.

    Args:
        queue: Asyncio queue that provides MachineInfo objects.
        table: Rich Table object of CRN resources.
        increment_progress_bar: Function to increment progress bar.
        valid_reward_addresses: Set of valid reward addresses to update.
    """
    while True:
        data: Union[MachineInfo, None, Literal["END_OF_QUEUE"]] = await queue.get()
        if data is None:
            continue
        elif data == "END_OF_QUEUE":
            break
        else:
            # assert False, data
            data = cast(MachineInfo, data)

            # node["hash"]
            cpu, hdd, ram = convert_system_info_to_str(data)
            # assert False, (cpu, hdd, ram)
            table.update_cell(row_key=data.hash, column_key="cpu", value=cpu, update_width=True)
            table.update_cell(row_key=data.hash, column_key="hdd", value=hdd, update_width=True)
            table.update_cell(row_key=data.hash, column_key="ram", value=ram, update_width=True)
            table.update_cell(row_key=data.hash, column_key="version", value=data.version, update_width=True)
            valid_reward_addresses.add(data.reward_address)


def convert_system_info_to_str(data: MachineInfo) -> Tuple[str, str, str]:
    """
    Converts MachineInfo object that contains CPU, RAM and HDD information to a tuple of strings.

    Args:
        data: Information obtained about the CRN.

    Returns:
        CPU, RAM, and HDD information as strings.
    """
    cpu: str = f"{data.machine_usage.cpu.count}"
    hdd: str = f"{data.machine_usage.disk.available_kB / 1_000_000:.0f} GB"
    ram: str = f"{data.machine_usage.mem.available_kB / 1_000_000:.0f} GB"

    return cpu, hdd, ram


from textual.app import App as TextualApp
from textual.widgets import Header, Footer, DataTable


class CRNTable(TextualApp):
    """Display Table and allow selection."""

    crns = {}
    is_loading = False

    def compose(self):
        """Create child widgets for the app."""

        yield ProgressBar()
        if self.is_loading:
            "Loading CRN Table..."
        else:
            self.table = DataTable(cursor_type="row", name="Select CRN")
            yield self.table
        yield Footer()

    async def on_mount(self):
        table = self.query_one(DataTable)
        table.add_column("Score", key="score")
        table.add_column("Reward Address")
        table.add_column("Name", key="name")
        table.add_column("Cores", key="cpu")
        table.add_column("RAM", key="ram")
        table.add_column("HDD", key="hdd")
        table.add_column("Version", key="version")
        table.add_column("URL")

        class CRNInfo(BaseModel):
            # machine_usage: MachineUsage
            score: float
            hash: str
            name: str
            version: typing.Optional[str]
            reward_address: str
            url: str

        self.is_loading = True
        nodes: NodeInfo = await _fetch_nodes()
        self.is_loading = False
        progress = self.query_one(ProgressBar)
        progress.total = len(nodes.data)
        for node in nodes.nodes:
            info = CRNInfo(
                hash=node["hash"],
                score=node["score"],
                name=node["name"],
                reward_address=node["reward"],
                url=node["address"],
            )
            # cpu, hdd, ram = convert_system_info_to_str(data)
            table.add_row(
                _format_score(info.score),
                info.reward_address,
                info.name,
                info.version,
                "",  # cpu,
                "",  # ram,
                "",  # hdd,
                info.url,
                key=info.hash,
            )
            self.crns[info.hash] = info

        # We use a queue in order to store retrieved data from the nodes not in order
        queue: MachineInfoQueue = asyncio.Queue()
        valid_reward_addresses: Set[str] = set()

        # for node in list(self.crns.values()):
        #     await asyncio.create_task(self.fetch_node_info(node))
        #
        # # The Live context manager allows us to update the table and progress bar in real time

        async def async_fetch_more_info_from_crn():
            await asyncio.gather(
                # Fetch CRN info from the nodes into the queue
                fetch_and_queue_crn_info(nodes, queue),
                # Update the table with the CRN info from the queue in parallel
                update_table(
                    queue,
                    self.table,
                    self.make_progress,
                    valid_reward_addresses,
                ),
            )

        await asyncio.create_task(async_fetch_more_info_from_crn())
        return

    async def fetch_node_info(self, node):
        # assert False
        try:
            node_url = sanitize_url(node.url)
        except InvalidURL:
            # logger.info(f"Invalid URL: {node['address']}")
            return

        # Skip nodes without a reward address
        if not node.reward_address:
            return

        # Fetch the machine usage and version from its HTTP API
        machine_usage, version = await fetch_crn_info(node_url)
        if not machine_usage:
            return

        data = MachineInfo.from_unsanitized_input(
            machine_usage=machine_usage,
            score=node.score,
            name=node.name,
            version=version,
            reward_address=node.reward_address,
            url=node.url,
            hash=node.hash,
        )
        cpu, hdd, ram = convert_system_info_to_str(data)
        print(cpu, hdd, ram)
        self.table.update_cell(row_key=data.hash, column_key="cpu", value=cpu)
        self.table.update_cell(row_key=data.hash, column_key="hdd", value=hdd)
        self.table.update_cell(row_key=data.hash, column_key="ram", value=ram)
        self.table.update_cell(row_key=data.hash, column_key="version", value=data.version)

    def make_progress(self) -> None:
        """Called automatically to advance the progress bar."""
        self.query_one(ProgressBar).advance(1)

    def on_data_table_row_selected(self, message: DataTable.RowSelected) -> None:
        self.row = message.row_key
        self.selected_crn = self.crns.get(message.row_key)
        print(self.selected_crn)
        self.exit(self.selected_crn)
