from __future__ import annotations

import asyncio
import logging
from typing import Dict, Optional, Set

from aleph_message.models import ItemHash
from pydantic import BaseModel
from textual.app import App
from textual.containers import Horizontal
from textual.css.query import NoMatches
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Label, ProgressBar
from textual.widgets._data_table import RowKey

from aleph_client.commands.instance.network import fetch_crn_info
from aleph_client.commands.node import NodeInfo, _fetch_nodes, _format_score
from aleph_client.models import MachineUsage
from aleph_client.utils import extract_valid_eth_address

logger = logging.getLogger(__name__)


class CRNInfo(BaseModel):
    score: float
    hash: ItemHash
    name: str
    version: Optional[str]
    stream_reward_address: str
    url: str
    machine_usage: Optional[MachineUsage]
    confidential_computing: Optional[bool]
    qemu_support: Optional[bool]

    @property
    def display_cpu(self) -> str:
        try:
            if self.machine_usage:
                return f"{self.machine_usage.cpu.count}"
        except:
            pass
        return ""

    @property
    def display_ram(self) -> str:
        try:
            if self.machine_usage:
                return f"{self.machine_usage.mem.available_kB / 1_000_000:.0f} / {self.machine_usage.mem.total_kB / 1_000_000:.0f} GB"
        except:
            pass
        return ""

    @property
    def display_hdd(self) -> str:
        try:
            if self.machine_usage:
                return f"{self.machine_usage.disk.available_kB / 1_000_000:.0f} / {self.machine_usage.disk.total_kB / 1_000_000:.0f} GB"
        except:
            pass
        return ""


class CRNTable(App[CRNInfo]):
    crns: Dict[RowKey, CRNInfo] = {}
    tasks: Set[asyncio.Task] = set()
    label_start = reactive("Loading CRNs list ")
    label_end = reactive("")
    table: DataTable
    total_crns: int
    active_crns: int = 0
    filtered_crns: int = 0
    only_confidentials: bool = False
    CSS = "#crn-table { align: center top; height: 95% }"
    BINDINGS = [
        ("s", "sort_by_score", "Sort By Score"),
        ("n", "sort_by_name", "Sort By Name"),
        ("v", "sort_by_version", "Sort By Version"),
        ("c", "sort_by_confidential_computing", "Sort By 🔒"),
        ("u", "sort_by_url", "Sort By URL"),
        ("q", "quit", "Quit"),
    ]
    current_sorts: set = set()

    def __init__(self, only_confidentials: bool = False):
        super().__init__()
        self.only_confidentials = only_confidentials

    def compose(self):
        """Create child widgets for the app."""
        self.table = DataTable(
            cursor_type="row",
            name="Select CRN",
            id="crn-table",
        )
        self.table.add_column("Score", key="score")
        self.table.add_column("Name", key="name")
        self.table.add_column("Version", key="version")
        self.table.add_column("Reward Address", key="stream_reward_address")
        self.table.add_column("🔒", key="confidential_computing")
        self.table.add_column("Qemu", key="qemu_support")
        self.table.add_column("Cores", key="cpu")
        self.table.add_column("RAM", key="ram")
        self.table.add_column("Disk", key="hdd")
        self.table.add_column("URL", key="url")
        yield Label("Choose a Compute Resource Node (CRN) to run your instance")
        with Horizontal():
            self.loader_label_start = Label(self.label_start)
            yield self.loader_label_start
            self.progress_bar = ProgressBar(show_eta=False)
            yield self.progress_bar
            self.loader_label_end = Label(self.label_end)
            yield self.loader_label_end
        yield self.table
        yield Footer()

    async def on_mount(self):
        task = asyncio.create_task(self.fetch_node_list())
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def fetch_node_list(self):
        nodes: NodeInfo = await _fetch_nodes()
        for node in nodes.nodes:
            self.crns[RowKey(node["hash"])] = CRNInfo(
                hash=node["hash"],
                score=node["score"],
                name=node["name"],
                stream_reward_address=node["stream_reward"],
                url=node["address"].rstrip("/"),
                machine_usage=None,
                version=None,
                confidential_computing=None,
                qemu_support=None,
            )

        # Initialize the progress bar
        self.total_crns = len(self.crns)
        self.progress_bar.total = self.total_crns
        self.loader_label_start.update(f"Fetching data of {self.total_crns} nodes ")
        self.tasks = set()

        # Fetch all CRNs
        for node in list(self.crns.values()):
            task = asyncio.create_task(self.fetch_node_info(node))
            self.tasks.add(task)
            task.add_done_callback(self.make_progress)
            task.add_done_callback(self.tasks.discard)

    async def fetch_node_info(self, node: CRNInfo):
        try:
            crn_info = await fetch_crn_info(node.url)
        except:
            return
        if crn_info:
            node.version = crn_info.get("version", "")
            node.stream_reward_address = extract_valid_eth_address(
                crn_info.get("payment", {}).get("PAYMENT_RECEIVER_ADDRESS") or node.stream_reward_address or ""
            )
            # The computing is only available on aleph-vm > 0.4.1
            node.confidential_computing = crn_info.get("computing", {}).get("ENABLE_CONFIDENTIAL_COMPUTING", False)
            node.qemu_support = crn_info.get("computing", {}).get("ENABLE_QEMU_SUPPORT", False)
            node.machine_usage = crn_info.get("machine_usage")

            # Skip nodes without a reward address
            if not node.stream_reward_address:
                logger.debug(f"Skipping node {node.hash}, no reward address")
                return
            # Skip nodes without machine usage
            if not node.machine_usage:
                logger.debug(f"Skipping node {node.hash}, no machine usage")
                return

            self.active_crns += 1
            # Skip non-confidential nodes if only_confidentials is set
            if self.only_confidentials and not node.confidential_computing:
                return
            self.filtered_crns += 1

            self.table.add_row(
                _format_score(node.score),
                node.name,
                node.version,
                node.stream_reward_address,
                "🟢" if node.confidential_computing else "🔴",
                "🟢" if node.qemu_support else "🔴",
                node.display_cpu,
                node.display_ram,
                node.display_hdd,
                node.url,
                key=node.hash,
            )

    def make_progress(self, task) -> None:
        """Called automatically to advance the progress bar."""
        try:
            self.progress_bar.advance(1)
            self.loader_label_end.update(f"    Available: {self.active_crns}    Match: {self.filtered_crns}")
        except NoMatches:
            pass
        if len(self.tasks) == 0:
            self.loader_label_start.update(f"Fetched {self.total_crns} nodes ")

    def on_data_table_row_selected(self, message: DataTable.RowSelected) -> None:
        """Return the selected row"""
        selected_crn: Optional[CRNInfo] = self.crns.get(message.row_key)
        self.exit(selected_crn)

    def sort_reverse(self, sort_type: str) -> bool:
        """Determine if `sort_type` is ascending or descending."""
        reverse = sort_type in self.current_sorts
        if reverse:
            self.current_sorts.remove(sort_type)
        else:
            self.current_sorts.add(sort_type)
        return reverse

    def sort_by(self, column, sort_func=lambda row: row.lower(), invert=False) -> None:
        table = self.query_one(DataTable)
        reverse = self.sort_reverse(column)
        table.sort(
            column,
            key=sort_func,
            reverse=not reverse if invert else reverse,
        )

    def action_sort_by_name(self) -> None:
        self.sort_by("name")

    def action_sort_by_score(self) -> None:
        self.sort_by("score", sort_func=lambda row: float(row.plain.rstrip("%")))

    def action_sort_by_version(self) -> None:
        self.sort_by("version")

    def action_sort_by_confidential_computing(self) -> None:
        self.sort_by("confidential_computing", invert=True)

    def action_sort_by_url(self) -> None:
        self.sort_by("url")
