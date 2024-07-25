from __future__ import annotations

import asyncio
import logging
from typing import Dict, Optional, Set, Tuple

from aiohttp import InvalidURL
from aleph_message.models import ItemHash
from pydantic import BaseModel
from textual.app import App
from textual.containers import Horizontal
from textual.css.query import NoMatches
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Label, ProgressBar
from textual.widgets._data_table import RowKey

from aleph_client.commands.instance.network import (
    fetch_crn_config,
    fetch_crn_info,
    sanitize_url,
)
from aleph_client.commands.node import NodeInfo, _fetch_nodes, _format_score
from aleph_client.models import MachineUsage

logger = logging.getLogger(__name__)


def convert_system_info_to_str(data: CRNInfo) -> Tuple[str, str, str]:
    """
    Converts MachineInfo object that contains CPU, RAM and HDD information to a tuple of strings.

    Args:
        data: Information obtained about the CRN.

    Returns:
        CPU, RAM, and HDD information as strings.
    """
    cpu: str = f"{data.machine_usage.cpu.count}" if data.machine_usage else "N/A"
    hdd: str = f"{data.machine_usage.disk.available_kB / 1_000_000:.0f} GB" if data.machine_usage else "N/A"
    ram: str = f"{data.machine_usage.mem.available_kB / 1_000_000:.0f} GB" if data.machine_usage else "N/A"

    return cpu, hdd, ram


class CRNInfo(BaseModel):
    machine_usage: Optional[MachineUsage]
    score: float
    hash: ItemHash
    name: str
    version: Optional[str]
    reward_address: str
    url: str
    confidential_computing: Optional[bool]


class DisplayMachineUsage(BaseModel):
    cpu: str = "N/A"
    mem: str = "N/A"
    disk: str = "N/A"


class CRNTable(App[CRNInfo]):
    crns: Dict[RowKey, CRNInfo] = {}
    tasks: Set[asyncio.Task] = set()
    text = reactive("Loading CRNs list ")
    table: DataTable

    def compose(self):
        """Create child widgets for the app."""
        self.table = DataTable(cursor_type="row", name="Select CRN")
        self.table.add_column("Score", key="score")
        self.table.add_column("Name", key="name")
        self.table.add_column("Reward Address")
        self.table.add_column("Confidential", key="confidential_computing")
        self.table.add_column("Cores", key="cpu")
        self.table.add_column("RAM", key="ram")
        self.table.add_column("HDD", key="hdd")
        self.table.add_column("Version", key="version")
        self.table.add_column("URL")
        yield Label("Choose a Compute Resource Node (CRN) to run your instance")
        with Horizontal():
            self.loader_label = Label(self.text)
            yield self.loader_label
            yield ProgressBar(show_eta=False)
        yield self.table
        yield Footer()

    async def on_mount(self):

        task = asyncio.create_task(self.fetch_node_list())
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def fetch_node_list(self):
        nodes: NodeInfo = await _fetch_nodes()

        for node in nodes.nodes:
            info = CRNInfo(
                hash=node["hash"],
                score=node["score"],
                name=node["name"],
                reward_address=node["reward"],
                url=node["address"],
                machine_usage=None,
                version=None,
                confidential_computing=None,
            )
            usage: DisplayMachineUsage = DisplayMachineUsage()

            if isinstance(info.machine_usage, MachineUsage):
                usage.disk = str(info.machine_usage.disk.available_kB)
                usage.mem = str(info.machine_usage.mem.available_kB)
                usage.cpu = str(info.machine_usage.cpu.count)

            self.table.add_row(
                _format_score(info.score),
                info.name,
                info.reward_address,
                info.confidential_computing,
                info.version,
                usage.cpu,
                usage.mem,
                usage.disk,
                info.url,
                key=info.hash,
            )
            self.crns[RowKey(info.hash)] = info

        progress = self.query_one(ProgressBar)
        progress.total = len(self.crns)
        # Retrieve more info by contacting each separate CRN in the background
        self.loader_label.update("Fetching information from each node ")
        self.tasks = set()
        for node in list(self.crns.values()):
            # Machine usage
            task = asyncio.create_task(self.fetch_node_info(node))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
            task.add_done_callback(self.make_progress)
            # Resource

            task = asyncio.create_task(self.fetch_node_config(node))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
            task.add_done_callback(self.make_progress)

    async def fetch_node_info(self, node: CRNInfo):
        try:
            node_url = sanitize_url(node.url)
        except InvalidURL:
            logger.debug(f"Skipping node {node.hash}, invalid url")
            return

        # Skip nodes without a reward address
        if not node.reward_address:
            logger.debug(f"Skipping node {node.hash}, no reward address")
            return

        # Fetch the machine usage and version from its HTTP API
        machine_usage, version = await fetch_crn_info(node_url)

        if not machine_usage:
            logger.debug(f"Skipping node {node.hash}, no machine usage")
            return
        node.machine_usage = MachineUsage.parse_obj(machine_usage)
        node.version = version

        cpu, hdd, ram = convert_system_info_to_str(node)

        self.table.update_cell(row_key=node.hash, column_key="cpu", value=cpu)
        self.table.update_cell(row_key=node.hash, column_key="hdd", value=hdd)
        self.table.update_cell(row_key=node.hash, column_key="ram", value=ram)
        self.table.update_cell(row_key=node.hash, column_key="version", value=node.version)

    async def fetch_node_config(self, node: CRNInfo):
        try:
            node_url = sanitize_url(node.url)
        except InvalidURL:
            logger.debug(f"Skipping node {node.hash}, invalid url")
            return

        # Skip nodes without a reward address
        if not node.reward_address:
            logger.debug(f"Skipping node {node.hash}, no reward address")
            return

        crn_config = await fetch_crn_config(node_url)
        if crn_config:
            # The computing is only available on aleph-vm > 0.4.1
            node.confidential_computing = crn_config.get("computing", {}).get("ENABLE_CONFIDENTIAL_COMPUTING")
        confidential_computing = "Y" if node.confidential_computing else "N"

        self.table.update_cell(row_key=node.hash, column_key="confidential_computing", value=confidential_computing)

    def on_data_table_row_selected(self, message: DataTable.RowSelected) -> None:
        """Return the selected row"""
        selected_crn: Optional[CRNInfo] = self.crns.get(message.row_key)
        self.exit(selected_crn)

    def make_progress(self, task) -> None:
        """Called automatically to advance the progress bar."""
        try:
            self.query_one(ProgressBar).advance(1)
        except NoMatches:
            pass
        if len(self.tasks) == 0:
            self.loader_label.update("Fetched ")
