import asyncio
from functools import partial
from typing import Callable, Literal, Set, Sized, Tuple, Union, cast

from rich.console import Console
from rich.live import Live
from rich.progress import Progress
from rich.table import Table

from aleph_client.commands.instance.network import (
    MachineInfoQueue,
    fetch_and_queue_crn_info,
)
from aleph_client.commands.node import NodeInfo, _fetch_nodes, _format_score
from aleph_client.models import MachineInfo


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
    table: Table,
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
        increment_progress_bar()
        if data is None:
            continue
        elif data == "END_OF_QUEUE":
            break
        else:
            data = cast(MachineInfo, data)
            cpu, hdd, ram = convert_system_info_to_str(data)
            table.add_row(
                _format_score(data.score),
                data.name,
                cpu,
                ram,
                hdd,
                data.version,
                data.reward_address,
                data.url,
            )
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
    hdd: str = f"{data.machine_usage.disk.available_kB / 1_000_000:.2f} GB"
    ram: str = f"{data.machine_usage.mem.available_kB / 1_000_000:.2f} GB"

    return cpu, hdd, ram


async def fetch_crn_info() -> set:
    """
    Fetches compute node information asynchronously.
    Display and update a Live tab where CRN info will be displayed

    Returns:
        List of valid reward addresses.
    """

    # Fetch node information from the API
    node_info: NodeInfo = await _fetch_nodes()

    # Create the console and progress table
    console = Console()
    progress_table, increment_progress_bar = create_table_with_progress_bar(node_info.nodes)
    valid_reward_addresses: Set[str] = set()

    # We use a queue in order to store retrieved data from the nodes not in order
    queue: MachineInfoQueue = asyncio.Queue()

    # The Live context manager allows us to update the table and progress bar in real time
    with Live(progress_table, console=console, refresh_per_second=2):
        await asyncio.gather(
            # Fetch CRN info from the nodes into the queue
            fetch_and_queue_crn_info(node_info, queue),
            # Update the table with the CRN info from the queue in parallel
            update_table(
                queue,
                progress_table.table,
                increment_progress_bar,
                valid_reward_addresses,
            ),
        )

    return valid_reward_addresses
