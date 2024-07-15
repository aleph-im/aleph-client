from __future__ import annotations

import asyncio
from typing import Optional, Tuple

from aiohttp import InvalidURL
from pydantic import BaseModel
from textual.app import App
from textual.containers import Horizontal
from textual.css.query import NoMatches
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Header, Label, ProgressBar

from aleph_client.commands.instance.network import fetch_crn_info, sanitize_url, fetch_crn_config
from aleph_client.commands.node import NodeInfo, _fetch_nodes, _format_score
from aleph_client.models import MachineUsage


def convert_system_info_to_str(data: CRNInfo) -> Tuple[str, str, str]:
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


class CRNInfo(BaseModel):
    machine_usage: Optional[MachineUsage]
    score: float
    hash: str
    name: str
    version: Optional[str]
    reward_address: str
    url: str
    confidential_computing: Optional[bool]


class CRNTable(App[CRNInfo]):
    """Display Table and allow selection."""

    crns = {}
    tasks = set()
    text = reactive("Loading CRNs list ")

    def compose(self):
        """Create child widgets for the app."""
        table = self.table = DataTable(cursor_type="row", name="Select CRN")
        table.add_column("Score", key="score")
        table.add_column("Name", key="name")
        table.add_column("Reward Address")
        table.add_column("Confidential Computing", key="confidential_computing")
        table.add_column("Cores", key="cpu")
        table.add_column("RAM", key="ram")
        table.add_column("HDD", key="hdd")
        table.add_column("Version", key="version")
        table.add_column("URL")
        yield Header()
        with Horizontal():
            yield Label(self.text)
            yield ProgressBar(show_eta=False)
        yield self.table
        yield Footer()

    async def on_mount(self):
        self.title = "Choose a Compute Resource Node (CRN) to run your instance"
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
            )
            self.table.add_row(
                _format_score(info.score),
                info.name,
                info.reward_address,
                "",  # info.confidential_computing,
                info.version,
                "",  # cpu,
                "",  # ram,
                "",  # hdd,
                info.url,
                key=info.hash,
            )
            self.crns[info.hash] = info

        progress = self.query_one(ProgressBar)
        progress.total = len(self.crns)

        # Retrieve more info by contacting each separate CRN in the background
        self.text = "Fetching CRN information... "
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
            return

        # Skip nodes without a reward address
        if not node.reward_address:
            return

        # Fetch the machine usage and version from its HTTP API
        machine_usage, version = await fetch_crn_info(node_url)

        if not machine_usage:
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
            return

        # Skip nodes without a reward address
        if not node.reward_address:
            return

        crn_config = await fetch_crn_config(node_url)
        if crn_config:
            # The computing is only available on aleph-vm > 0.4.1
            node.confidential_computing = crn_config.get("computing", {}).get("ENABLE_CONFIDENTIAL_COMPUTING")
        confidential_computing = "Y" if node.confidential_computing else "N"

        self.table.update_cell(row_key=node.hash, column_key="confidential_computing", value=confidential_computing)

    def on_data_table_row_selected(self, message: DataTable.RowSelected) -> None:
        """Return the selected row"""
        selected_crn = self.crns.get(message.row_key)
        self.exit(selected_crn)

    def make_progress(self, task) -> None:
        """Called automatically to advance the progress bar."""
        try:
            self.query_one(ProgressBar).advance(1)
        except NoMatches:
            pass
