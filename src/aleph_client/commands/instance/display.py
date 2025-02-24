from __future__ import annotations

import asyncio
import logging
from typing import Optional

from textual.app import App
from textual.containers import Horizontal
from textual.css.query import NoMatches
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Label, ProgressBar
from textual.widgets._data_table import RowKey

from aleph_client.commands.instance.network import (
    fetch_crn_list,
    fetch_latest_crn_version,
)
from aleph_client.commands.node import _format_score
from aleph_client.models import CRNInfo

logger = logging.getLogger(__name__)


class CRNTable(App[tuple[CRNInfo, int]]):
    table: DataTable
    tasks: set[asyncio.Task] = set()
    crns: dict[RowKey, tuple[CRNInfo, int]] = {}
    current_crn_version: str
    total_crns: int
    active_crns: int = 0
    filtered_crns: int = 0
    label_start = reactive("Loading CRNs list ")
    label_end = reactive("")
    only_reward_address: bool = False
    only_qemu: bool = False
    only_confidentials: bool = False
    only_gpu: bool = False
    only_gpu_model: Optional[str] = None
    current_sorts: set = set()
    loader_label_start: Label
    loader_label_end: Label
    progress_bar: ProgressBar

    BINDINGS = [
        ("s", "sort_by_score", "Sort By Score"),
        ("n", "sort_by_name", "Sort By Name"),
        ("v", "sort_by_version", "Sort By Version"),
        ("a", "sort_by_address", "Sort By Address"),
        ("c", "sort_by_confidential", "Sort By 🔒 Confidential"),
        ## ("q", "sort_by_qemu", "Sort By Qemu"),
        ("g", "sort_by_gpu", "Sort By GPU"),
        ("u", "sort_by_url", "Sort By URL"),
        ("x", "quit", "Exit"),
    ]

    def __init__(
        self,
        only_latest_crn_version: bool = False,
        only_reward_address: bool = False,
        only_qemu: bool = False,
        only_confidentials: bool = False,
        only_gpu: bool = False,
        only_gpu_model: Optional[str] = None,
    ):
        super().__init__()
        self.only_latest_crn_version = only_latest_crn_version
        self.only_reward_address = only_reward_address
        self.only_qemu = only_qemu
        self.only_confidentials = only_confidentials
        self.only_gpu = only_gpu
        self.only_gpu_model = only_gpu_model

    def compose(self):
        """Create child widgets for the app."""
        self.table = DataTable(cursor_type="row", name="Select CRN")
        self.table.add_column("Score", key="score")
        self.table.add_column("Name", key="name")
        self.table.add_column("Version", key="version")
        self.table.add_column("Reward Address", key="stream_reward_address")
        self.table.add_column("🔒", key="confidential_computing")
        self.table.add_column("GPU", key="gpu_support")
        ## self.table.add_column("Qemu", key="qemu_support") ## Qemu computing enabled by default on CRNs
        self.table.add_column("Cores", key="cpu")
        self.table.add_column("Free RAM 🌡", key="ram")
        self.table.add_column("Free Disk 💿", key="hdd")
        self.table.add_column("URL", key="url")
        self.table.add_column("Terms & Conditions 📝", key="tac")
        yield Label(
            f"Choose a Compute Resource Node (CRN) {'x GPU ' if self.only_gpu_model else ''}to run your instance"
        )
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
        crn_list = await fetch_crn_list()
        self.crns = (
            {RowKey(crn.hash): (crn, 0) for crn in crn_list}
            if not self.only_gpu_model
            else {
                RowKey(f"{crn.hash}_{gpu_id}"): (crn, gpu_id)
                for crn in crn_list
                for gpu_id in range(len(crn.compatible_available_gpus))
            }
        )
        self.current_crn_version = await fetch_latest_crn_version()

        # Initialize the progress bar
        self.total_crns = len(self.crns)
        self.progress_bar.total = self.total_crns
        self.loader_label_start.update(
            f"Fetching data of {self.total_crns} CRNs {'x GPUs ' if self.only_gpu_model else ''}"
        )
        self.tasks = set()

        # Fetch all CRNs
        for crn, gpu_id in list(self.crns.values()):
            task = asyncio.create_task(self.add_crn_info(crn, gpu_id))
            self.tasks.add(task)
            task.add_done_callback(self.make_progress)
            task.add_done_callback(self.tasks.discard)

    async def add_crn_info(self, crn: CRNInfo, gpu_id: int):
        self.active_crns += 1
        # Skip CRNs with legacy version
        if self.only_latest_crn_version and crn.version < self.current_crn_version:
            logger.debug(f"Skipping CRN {crn.hash}, legacy version")
            return
        # Skip CRNs without machine usage
        if not crn.machine_usage:
            logger.debug(f"Skipping CRN {crn.hash}, no machine usage")
            return
        # Skip CRNs without ipv6 connectivity
        if not crn.ipv6:
            logger.debug(f"Skipping CRN {crn.hash}, no ipv6 connectivity")
            return
        # Skip CRNs without reward address if only_reward_address is set
        if self.only_reward_address and not crn.stream_reward_address:
            logger.debug(f"Skipping CRN {crn.hash}, no reward address")
            return
        # Skip non-qemu CRNs if only_qemu is set
        if self.only_qemu and not crn.qemu_support:
            logger.debug(f"Skipping CRN {crn.hash}, no qemu support")
            return
        # Skip non-confidential CRNs if only_confidentials is set
        if self.only_confidentials and not crn.confidential_computing:
            logger.debug(f"Skipping CRN {crn.hash}, no confidential support")
            return
        # Skip non-gpu CRNs if only-gpu is set
        if self.only_gpu and not (crn.gpu_support and crn.compatible_available_gpus):
            logger.debug(f"Skipping CRN {crn.hash}, no GPU support or without GPU available")
            return
        # Skip CRNs without compatible GPU if only-gpu-model is set
        elif (
            self.only_gpu
            and self.only_gpu_model
            and self.only_gpu_model != crn.compatible_available_gpus[gpu_id]["model"]
        ):
            logger.debug(f"Skipping CRN {crn.hash}, no {self.only_gpu_model} GPU support")
            return
        self.filtered_crns += 1

        # Fetch terms and conditions
        tac = await crn.terms_and_conditions_content

        self.table.add_row(
            _format_score(crn.score),
            crn.name,
            crn.version,
            crn.stream_reward_address,
            "✅" if crn.confidential_computing else "✖",
            # "✅" if crn.qemu_support else "✖", ## Qemu computing enabled by default on crns
            (
                crn.compatible_available_gpus[gpu_id]["device_name"]
                if self.only_gpu_model
                else "✅" if crn.gpu_support else "✖"
            ),
            crn.display_cpu,
            crn.display_ram,
            crn.display_hdd,
            crn.url,
            tac.url if tac else "✖",
            key=f"{crn.hash}_{gpu_id}" if self.only_gpu_model else crn.hash,
        )

    def make_progress(self, task):
        """Called automatically to advance the progress bar."""
        try:
            self.progress_bar.advance(1)
            self.loader_label_end.update(f"    Available: {self.active_crns}    Match: {self.filtered_crns}")
        except NoMatches:
            pass
        if len(self.tasks) == 0:
            self.loader_label_start.update(f"Fetched {self.total_crns} CRNs ")

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

    def action_sort_by_gpu(self):
        self.sort_by("gpu_support")

    def action_sort_by_url(self):
        self.sort_by("url")
