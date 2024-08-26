from __future__ import annotations

import asyncio
import logging
from typing import Dict, Optional, Set

from textual.app import App
from textual.containers import Horizontal
from textual.css.query import NoMatches
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Label, ProgressBar
from textual.widgets._data_table import RowKey

from aleph_client.commands.instance.network import fetch_crn_info
from aleph_client.commands.node import NodeInfo, _fetch_nodes, _format_score
from aleph_client.models import CRNInfo
from aleph_client.utils import extract_valid_eth_address

logger = logging.getLogger(__name__)


class CRNTable(App[CRNInfo]):
    table: DataTable
    tasks: Set[asyncio.Task] = set()
    crns: Dict[RowKey, CRNInfo] = {}
    total_crns: int
    active_crns: int = 0
    filtered_crns: int = 0
    label_start = reactive("Loading CRNs list ")
    label_end = reactive("")
    only_reward_address: bool = False
    only_qemu: bool = False
    only_confidentials: bool = False
    current_sorts: set = set()
    BINDINGS = [
        ("s", "sort_by_score", "Sort By Score"),
        ("n", "sort_by_name", "Sort By Name"),
        ("v", "sort_by_version", "Sort By Version"),
        ("a", "sort_by_address", "Sort By Address"),
        ("c", "sort_by_confidential", "Sort By 🔒 Confidential"),
        ("q", "sort_by_qemu", "Sort By Qemu"),
        ("u", "sort_by_url", "Sort By URL"),
        ("x", "quit", "Exit"),
    ]

    def __init__(self, only_reward_address: bool = False, only_qemu: bool = False, only_confidentials: bool = False):
        super().__init__()
        self.only_reward_address = only_reward_address
        self.only_qemu = only_qemu
        self.only_confidentials = only_confidentials

    def compose(self):
        """Create child widgets for the app."""
        self.table = DataTable(cursor_type="row", name="Select CRN")
        self.table.add_column("Score", key="score")
        self.table.add_column("Name", key="name")
        self.table.add_column("Version", key="version")
        self.table.add_column("Reward Address", key="stream_reward_address")
        self.table.add_column("🔒", key="confidential_computing")
        self.table.add_column("Qemu", key="qemu_support")
        self.table.add_column("Cores", key="cpu")
        self.table.add_column("Free RAM 🌡", key="ram")
        self.table.add_column("Free Disk 💿", key="hdd")
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
        self.table.styles.height = "95%"
        task = asyncio.create_task(self.fetch_node_list())
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def fetch_node_list(self):
        nodes: NodeInfo = await _fetch_nodes()
        for node in nodes.nodes:
            self.crns[RowKey(node["hash"])] = CRNInfo(
                hash=node["hash"],
                name=node["name"],
                url=node["address"].rstrip("/"),
                version=None,
                score=node["score"],
                stream_reward_address=node["stream_reward"],
                machine_usage=None,
                qemu_support=None,
                confidential_computing=None,
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
            node.qemu_support = crn_info.get("computing", {}).get("ENABLE_QEMU_SUPPORT", False)
            node.confidential_computing = crn_info.get("computing", {}).get("ENABLE_CONFIDENTIAL_COMPUTING", False)
            node.machine_usage = crn_info.get("machine_usage")

            # Skip nodes without machine usage
            if not node.machine_usage:
                logger.debug(f"Skipping node {node.hash}, no machine usage")
                return

            self.active_crns += 1
            # Skip nodes without reward address if only_reward_address is set
            if self.only_reward_address and not node.stream_reward_address:
                logger.debug(f"Skipping node {node.hash}, no reward address")
                return
            # Skip non-qemu nodes if only_qemu is set
            if self.only_qemu and not node.qemu_support:
                logger.debug(f"Skipping node {node.hash}, no qemu support")
                return
            # Skip non-confidential nodes if only_confidentials is set
            if self.only_confidentials and not node.confidential_computing:
                logger.debug(f"Skipping node {node.hash}, no confidential support")
                return
            self.filtered_crns += 1

            self.table.add_row(
                _format_score(node.score),
                node.name,
                node.version,
                node.stream_reward_address,
                "✅" if node.confidential_computing else "✖",
                "✅" if node.qemu_support else "✖",
                node.display_cpu,
                node.display_ram,
                node.display_hdd,
                node.url,
                key=node.hash,
            )

    def make_progress(self, task):
        """Called automatically to advance the progress bar."""
        try:
            self.progress_bar.advance(1)
            self.loader_label_end.update(f"    Available: {self.active_crns}    Match: {self.filtered_crns}")
        except NoMatches:
            pass
        if len(self.tasks) == 0:
            self.loader_label_start.update(f"Fetched {self.total_crns} nodes ")

    def on_data_table_row_selected(self, message: DataTable.RowSelected):
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

    def sort_by(self, column, sort_func=lambda row: row.lower(), invert=False):
        table = self.query_one(DataTable)
        reverse = self.sort_reverse(column)
        table.sort(
            column,
            key=sort_func,
            reverse=not reverse if invert else reverse,
        )

    def action_sort_by_score(self):
        self.sort_by("score", sort_func=lambda row: float(row.plain.rstrip("%")), invert=True)

    def action_sort_by_name(self):
        self.sort_by("name")

    def action_sort_by_version(self):
        self.sort_by("version")

    def action_sort_by_address(self):
        self.sort_by("stream_reward_address")

    def action_sort_by_confidential(self):
        self.sort_by("confidential_computing")

    def action_sort_by_qemu(self):
        self.sort_by("qemu_support")

    def action_sort_by_url(self):
        self.sort_by("url")
