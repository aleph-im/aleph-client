from __future__ import annotations

import asyncio
import logging
from decimal import Decimal
from typing import Optional, Union, cast

from aleph.sdk.client.http import AlephHttpClient
from aleph.sdk.query.responses import PriceResponse
from aleph.sdk.types import (
    CrnExecutionV1,
    CrnExecutionV2,
    InstanceAllocationsInfo,
    InstanceManual,
    InstancesExecutionList,
    InstanceWithScheduler,
    VmStatus,
)
from aleph.sdk.utils import displayable_amount, safe_getattr
from aleph_message.models import InstanceMessage
from aleph_message.models.execution.base import PaymentType
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textual.app import App
from textual.containers import Horizontal
from textual.css.query import NoMatches
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Label, ProgressBar
from textual.widgets._data_table import RowKey

from aleph_client.commands.files import download
from aleph_client.commands.help_strings import ALLOCATION_AUTO, ALLOCATION_MANUAL
from aleph_client.commands.instance.network import fetch_crn_list
from aleph_client.commands.node import _format_score
from aleph_client.models import CRNInfo

logger = logging.getLogger(__name__)


def display_vm_status(status: VmStatus) -> Text:
    """Display the VM status as a rich Text object with appropriate styling.

    Args:
        status: VmStatus object containing status information

    Returns:
        Formatted Text object with status display
    """
    if all(getattr(status, key) is None for key in vars(status)):
        return Text.from_markup("[bold yellow]NOT ALLOCATED[/bold yellow]")

    if status.stopped_at:
        return Text.from_markup("[bold red]STOPPED[/bold red]")

    if status.stopping_at:
        return Text.from_markup("[bold yellow]STOPPING[/bold yellow] ⏳")

    if status.started_at:
        return Text.from_markup("[bold green]RUNNING[/bold green]")

    if status.preparing_at:
        return Text.from_markup("[bold yellow]PREPARING[/bold yellow] ⏳")

    return Text.from_markup("[bold yellow]NOT ALLOCATED[/bold yellow]")


class InstanceTableBuilder:
    """Builder class for constructing the instance display table"""

    def __init__(
        self, messages: list[InstanceMessage], allocations: InstanceAllocationsInfo, executions: InstancesExecutionList
    ):
        self.messages = messages
        self.allocations = allocations
        self.executions = executions
        self.console = Console()

        # Tracking unallocated instances
        self.uninitialized_confidential_found: list[str] = []
        self.unallocated_payg_found: list[str] = []
        self.unallocated_gpu_found: list[str] = []
        self.unallocated_hold: list[str] = []

        # Create the table
        self.table = self._create_table()

    def _create_table(self) -> Table:
        """Create and initialize the table structure"""
        table = Table(box=box.ROUNDED, style="blue_violet")

        # Check if executions has a root attribute before accessing it
        num_executions = len(self.executions.root) if hasattr(self.executions, "root") else 0
        num_allocations = len(self.allocations.root)

        table.add_column(f"Instances [{num_executions} / {num_allocations}]", style="blue", overflow="fold")
        table.add_column("Specifications", style="blue")
        table.add_column("Allocation", style="blue", overflow="fold")
        table.add_column("Execution", style="blue", overflow="crop", width=60)

        return table

    async def build(self) -> Table:
        """Build the complete table with all instances"""
        for message in self.messages:
            allocation = self.allocations.root.get(message.item_hash, None)
            execution = self.executions.root.get(message.item_hash, None)

            instance_display = InstanceDisplay(message, allocation, execution)
            await instance_display.prepare()

            # Track unallocated instances for later display
            if allocation and not execution:
                if not instance_display.is_hold:
                    self.unallocated_payg_found.append(message.item_hash)
                elif instance_display.is_confidential:
                    self.unallocated_payg_found.append(message.item_hash)
                elif instance_display.has_gpu:
                    self.unallocated_gpu_found.append(message.item_hash)
                else:
                    self.unallocated_hold.append(message.item_hash)

            # Add the row to the table
            self.table.add_row(
                instance_display.instance_column,
                instance_display.specifications_column,
                instance_display.allocation_column,
                instance_display.execution_column,
            )
            self.table.add_section()

        return self.table

    def display_summary_panel(self):
        """Display the summary panel with additional information"""
        if not self.messages:
            return

        infos = [Text.from_markup(f"[bold]Address:[/bold] [bright_cyan]{self.messages[0].sender}[/bright_cyan]")]

        if self.unallocated_payg_found:
            unallocated_payg_found_str = "\n".join(self.unallocated_payg_found)
            infos += [
                Text.assemble(
                    Text.from_markup("\n\nYou have unallocated/unstarted instance(s) with active flows:\n"),
                    Text.from_markup(f"[bright_red]{unallocated_payg_found_str}[/bright_red]"),
                    Text.from_markup(
                        "\n[italic]↳[/italic] [orange3]Recommended action:[/orange3] allocate + start, or delete them."
                    ),
                )
            ]

        if self.uninitialized_confidential_found:
            uninitialized_confidential_found_str = "\n".join(self.uninitialized_confidential_found)
            infos += [
                Text.assemble(
                    "\n\nBoot unallocated/unstarted confidential instance(s):\n",
                    Text.from_markup(f"[grey50]{uninitialized_confidential_found_str}[/grey50]"),
                    Text.from_markup(
                        "\n↳ aleph instance confidential [bright_cyan]<vm-item-hash>[/bright_cyan]", style="italic"
                    ),
                )
            ]

        infos += [
            Text.assemble(
                "\n\nConnect to an instance with:\n",
                Text.from_markup(
                    "↳ ssh root@[yellow]<ipv6-address>[/yellow] [-i [orange3]<ssh-private-key-file>[/orange3]]",
                    style="italic",
                ),
                "\nor with IPv4 (when available):\n",
                Text.from_markup(
                    (
                        "↳ ssh root@[bright_green]<ipv4-address>[/bright_green] "
                        "[-i [orange3]<ssh-private-key-file>[/orange3]]"
                    ),
                    style="italic",
                ),
            )
        ]

        self.console.print(
            Panel(Text.assemble(*infos), title="Infos", border_style="bright_cyan", expand=False, title_align="left")
        )


class InstanceDisplay:
    """Class for displaying an individual instance"""

    def __init__(
        self,
        message: InstanceMessage,
        allocation: Union[InstanceManual, InstanceWithScheduler, None],
        execution: Union[CrnExecutionV1, CrnExecutionV2, None],
    ):
        self.message = message
        self.allocation = allocation
        self.execution = execution

        # Instance properties
        self.is_hold = message.content.payment and message.content.payment.type == PaymentType.hold.value
        self.firmware = safe_getattr(message.content.environment, "trusted_execution.firmware")
        self.is_confidential = self.firmware and len(self.firmware) == 64
        self.has_gpu = True if safe_getattr(message.content.requirements, "gpu") else False
        self.tac_hash = safe_getattr(message.content.requirements, "node.terms_and_conditions")
        self.tac_url: Optional[str] = None
        self.tac_accepted: bool = False

        # Columns to display
        self.instance_column: Optional[Text] = None
        self.specifications_column: Optional[Text] = None
        self.allocation_column: Optional[Text] = None
        self.execution_column: Optional[Text] = None

    async def prepare(self):
        """Prepare all display columns for this instance"""
        if self.tac_hash:
            tac = await download(self.tac_hash, only_info=True, verbose=False)
            tac_url = safe_getattr(tac, "url")
            self.tac_url = str(tac_url) if tac_url else f"missing → {self.tac_hash}"
            if tac_url:
                self.tac_accepted = True

        await self._prepare_instance_column()
        self._prepare_specifications_column()
        self._prepare_allocation_column()
        self._prepare_execution_column()

    async def _prepare_instance_column(self):
        """Prepare the main instance information column"""
        # Display name with status badge if applicable
        name = Text(
            (
                self.message.content.metadata["name"]
                if hasattr(self.message.content, "metadata")
                and isinstance(self.message.content.metadata, dict)
                and "name" in self.message.content.metadata
                else "-"
            ),
            style="magenta3",
        )

        if isinstance(self.execution, CrnExecutionV2) and hasattr(self.execution, "status"):
            status_badge = display_vm_status(self.execution.status)
            # Align like a badge, tab-separated
            name = Text.assemble(name, "\t", status_badge)

        # Item hash with explorer link
        link = f"https://explorer.aleph.im/address/ETH/{self.message.sender}/message/INSTANCE/{self.message.item_hash}"
        item_hash_link = Text.from_markup(f"[link={link}]{self.message.item_hash}[/link]", style="bright_cyan")

        # Payment information
        payment = Text.assemble(
            "Payment: ",
            Text(
                self.message.content.payment.type.capitalize().ljust(12) if self.message.content.payment else "",
                style="red" if self.is_hold else "orange3",
            ),
        )

        # VM type (confidential or regular)
        confidential = Text.assemble(
            "Type: ",
            Text("Confidential", style="green") if self.is_confidential else Text("Regular", style="grey50"),
        )

        # Chain information
        chain = Text.assemble("Chain: ", Text(self.message.chain.value.ljust(14), style="white"))

        # Creation timestamp
        created_at = Text.assemble("Created at: ", Text(str(self.message.time), style="magenta3"))

        # Payer information if different from sender
        payer = Text("")
        if self.message.sender != self.message.content.address:
            payer = Text.assemble("\nPayer: ", Text(str(self.message.content.address)))

        # Price information
        async with AlephHttpClient() as client:
            price: PriceResponse = await client.get_program_price(self.message.item_hash)
            required_tokens = Decimal(price.required_tokens)

        if self.is_hold:
            aleph_price = Text(f"{displayable_amount(required_tokens, decimals=3)} (fixed)", style="magenta3")
        else:
            psec = f"{displayable_amount(required_tokens, decimals=8)}/sec"
            phour = f"{displayable_amount(3600*required_tokens, decimals=3)}/hour"
            pday = f"{displayable_amount(86400*required_tokens, decimals=3)}/day"
            pmonth = f"{displayable_amount(2628000*required_tokens, decimals=3)}/month"
            aleph_price = Text.assemble(psec, " | ", phour, " | ", pday, " | ", pmonth, style="magenta3")

        cost = Text.assemble("\n$ALEPH: ", aleph_price)

        # Assemble the complete instance column
        result = Text.assemble(
            "Item Hash ↓\t     Name: ",
            name,
            "\n",
            item_hash_link,
            "\n",
            payment,
            confidential,
            "\n",
            chain,
            created_at,
            payer,
            cost,
        )
        self.instance_column = cast(Text, result if result else Text(""))

    def _prepare_specifications_column(self):
        """Prepare the specifications column showing hardware details"""
        hypervisor = safe_getattr(self.message, "content.environment.hypervisor")
        specs = [
            f"vCPU: [magenta3]{self.message.content.resources.vcpus}[/magenta3]\n",
            f"RAM: [magenta3]{self.message.content.resources.memory / 1_024:.2f} GiB[/magenta3]\n",
            f"Disk: [magenta3]{self.message.content.rootfs.size_mib / 1_024:.2f} GiB[/magenta3]\n",
            f"HyperV: [magenta3]{hypervisor.capitalize() if hypervisor else 'Firecracker'}[/magenta3]",
        ]

        # Add GPU information if present
        gpus = safe_getattr(self.message, "content.requirements.gpu")
        if gpus:
            specs += [f"\n[bright_yellow]GPU [[green]{len(gpus)}[/green]]:\n"]
            for gpu in gpus:
                specs += [f"• [green]{gpu.vendor}, {gpu.device_name}[green]"]
            specs += ["[/bright_yellow]"]

        self.specifications_column = cast(Text, Text.from_markup("".join(specs)) or Text(""))

    def _prepare_allocation_column(self):
        """Prepare the allocation column showing node allocation details"""
        if not self.allocation:
            self.allocation_column = cast(Text, Text.from_markup("[red]Not allocated[/red]"))
            return

        # Get allocation details based on allocation type
        if isinstance(self.allocation, InstanceManual):
            crn_url = self.allocation.crn_url
            allocation_str = ALLOCATION_MANUAL
            color_allocation = "magenta3"
            crn_hash = safe_getattr(self.message.content.requirements, "node.node_hash") or ""
        else:
            crn_url = self.allocation.allocations.node.url
            allocation_str = ALLOCATION_AUTO
            color_allocation = "deep_sky_blue1"
            crn_hash = self.allocation.allocations.node.node_id

        # Assemble the complete allocation column
        self.allocation_column = cast(
            Text,
            Text.assemble(
                Text.assemble(
                    Text("Allocation: ", style="blue"),
                    Text(
                        allocation_str + "\n",
                        style=color_allocation,
                    ),
                ),
                (
                    Text.assemble(
                        Text(
                            f"CRN {'Hash' if isinstance(self.allocation, InstanceManual) else 'Name'}: ", style="blue"
                        ),
                        Text(crn_hash + "\n", style=("bright_cyan")),
                    )
                ),
                Text.assemble(
                    Text("CRN Url: ", style="blue"),
                    Text(
                        crn_url + "\n",
                        style="green1" if crn_url.startswith("http") else "grey50",
                    ),
                ),
            )
            or Text(""),
        )

    def _prepare_execution_column(self):
        """Prepare the execution column showing runtime details"""
        if isinstance(self.execution, CrnExecutionV1):
            self._prepare_execution_v1_column()
        elif isinstance(self.execution, CrnExecutionV2):
            self._prepare_execution_v2_column()
        else:
            self._prepare_no_execution_column()

    def _prepare_execution_v1_column(self):
        """Prepare execution column for V1 execution type"""
        if not self.execution or not hasattr(self.execution, "networking"):
            self.execution_column = cast(Text, Text.from_markup("[red]No networking information available[/red]"))
            return

        ipv6_logs = safe_getattr(self.execution.networking, "ipv6")
        ipv4 = safe_getattr(self.execution.networking, "ipv4")

        self.execution_column = cast(
            Text,
            Text.assemble(
                (
                    Text.assemble(
                        Text("IPv6: ", style="blue"),
                        Text(
                            ipv6_logs,
                            style=(
                                "bright_yellow"
                                if ipv6_logs and ":" in ipv6_logs and len(ipv6_logs.split(":")) == 8
                                else "dark_orange"
                            ),
                        ),
                    )
                    if ipv6_logs
                    else ""
                ),
                # Display IPv4 address if available
                (
                    Text.assemble(
                        Text("\nIPv4: ", style="blue"),
                        Text(ipv4, style="bright_green" if ipv4 and "." in ipv4 else "dark_orange"),
                    )
                    if ipv4
                    else ""
                ),
            )
            or Text(""),
        )

    def _prepare_execution_v2_column(self):
        """Prepare execution column for V2 execution type"""
        if not self.execution or not hasattr(self.execution, "networking"):
            self.execution_column = cast(Text, Text.from_markup("[red]No networking information available[/red]"))
            return

        ipv4_network = safe_getattr(self.execution.networking, "ipv4_network")
        ipv6_network = safe_getattr(self.execution.networking, "ipv6_network")
        host_ipv4 = safe_getattr(self.execution.networking, "host_ipv4")
        ipv6_ip = safe_getattr(self.execution.networking, "ipv6_ip")
        mapped_ports = safe_getattr(self.execution.networking, "mapped_ports") or {}

        # Prepare port mappings display
        port_texts = []
        for container_port, mapping in mapped_ports.items():
            port_text = Text.assemble(
                Text(f"\n  ↪ {container_port} -> Host {mapping.host}", style="cyan"),
                Text(" [TCP]" if mapping.tcp else "", style="green"),
                Text(" [UDP]" if mapping.udp else "", style="magenta"),
            )
            port_texts.append(port_text)

        # Prepare SSH connection help
        ssh_help = []
        login_info = Text.assemble("\nConnections Details : ", style="blue")
        ssh_help.append(login_info)

        port_22_mapping = mapped_ports.get("22")
        if port_22_mapping and host_ipv4:
            ssh_ipv4_cmd = f"ssh root@{host_ipv4} -p {port_22_mapping.host} -i <ssh-private-key-file>"
            ssh_ipv4 = Text.from_markup(
                f"\n↳ {ssh_ipv4_cmd}",
                style="italic",
            )
            ssh_help.append(ssh_ipv4)

        if ipv6_ip:
            ssh_ipv6_cmd = f"ssh root@{ipv6_ip} -i <ssh-private-key-file>"
            ssh_ipv6 = Text.from_markup(
                f"\n↳ {ssh_ipv6_cmd}",
                style="italic",
            )
            ssh_help.append(ssh_ipv6)

        # Assemble the complete execution column
        self.execution_column = cast(
            Text,
            Text.assemble(
                Text.assemble(
                    Text("IPv4 Network: ", style="blue"),
                    Text(ipv4_network or "N/A", style="bright_green" if ipv4_network else "dark_orange"),
                    Text("\nHost IPv4: ", style="blue"),
                    Text(host_ipv4 or "N/A", style="bright_green" if host_ipv4 else "dark_orange"),
                    Text("\nIPv6 Network: ", style="blue"),
                    Text(ipv6_network or "N/A", style="bright_yellow" if ipv6_network else "dark_orange"),
                    Text("\nIPv6 IP: ", style="blue"),
                    Text(ipv6_ip or "N/A", style="bright_yellow" if ipv6_ip else "dark_orange"),
                    Text("\nMapped Ports:", style="blue"),
                ),
                *port_texts,
                *ssh_help,
            )
            or Text(""),
        )

    def _prepare_no_execution_column(self):
        """Prepare execution column when no execution is present"""
        if not self.allocation:
            self.execution_column = cast(Text, Text.from_markup("[red]Not allocated[/red]"))
            return

        if isinstance(self.allocation, InstanceManual):
            if self.is_confidential:
                self.execution_column = cast(
                    Text,
                    Text.from_markup(
                        "[italic]↳ aleph instance confidential [bright_cyan]<vm-item-hash>[/bright_cyan][/italic]"
                    ),
                )
            else:
                self.execution_column = cast(
                    Text,
                    Text.assemble(
                        Text("Please make sure PAYG flow is running", style="orange3"),
                        Text.from_markup(
                            "\n[italic]↳[/italic] [orange3]Recommended action:[/orange3] \n"
                            " ↳ aleph instance allocate [bright_cyan]<vm-item-hash>[/bright_cyan] \n"
                            " ↳ aleph instance start [bright_cyan]<vm-item-hash>[/bright_cyan])"
                        ),
                    )
                    or Text(""),
                )
        else:
            # The VM could be on this case if the VM is getting scheduled at the moment of the request
            # Or the CRN have an issue
            self.execution_column = cast(
                Text,
                Text.assemble(
                    Text("Instances could have an issue", style="orange3"),
                    Text.from_markup(
                        "\n[italic]↳[/italic] [orange3]Recommended action:[/orange3] \n"
                        " Wait instances to get executed \n"
                        " or ↳ aleph instance delete [bright_cyan]<vm-item-hash>[/bright_cyan] \n"
                        " ↳ aleph instance create"
                    ),
                )
                or Text(""),
            )


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
        # self.current_crn_version = await fetch_latest_crn_version()
        # Relax current filter to allow use aleph-vm versions since 1.5.1.
        # TODO: Allow to specify that option on settings aggregate on maybe on GitHub
        self.current_crn_version = "1.5.1"

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
        if self.only_latest_crn_version and (crn.version or "0.0.0") < self.current_crn_version:
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


async def show_instances(
    messages: list[InstanceMessage], allocations: InstanceAllocationsInfo, executions: InstancesExecutionList
):
    """Display instance information in a table format.

    Args:
        messages: List of instance messages
        allocations: Information about instance allocations
        executions: Information about instance executions
    """
    table_builder = InstanceTableBuilder(messages, allocations, executions)
    table = await table_builder.build()

    console = Console()
    console.print(table)

    table_builder.display_summary_panel()
