from datetime import datetime
from typing import Any, Optional

from aiohttp import InvalidURL
from aleph.sdk.types import StoredContent
from aleph_message.models import ItemHash
from aleph_message.models.execution.environment import CpuProperties, GpuDeviceClass
from pydantic import BaseModel
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text
from typer import echo

from aleph_client.commands.files import download
from aleph_client.commands.node import _escape_and_normalize, _remove_ansi_escape
from aleph_client.utils import extract_valid_eth_address, sanitize_url


class LoadAverage(BaseModel):
    load1: float
    load5: float
    load15: float


class CoreFrequencies(BaseModel):
    min: float
    max: float


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


class GpuDevice(BaseModel):
    vendor: str
    model: str
    device_name: str
    device_class: GpuDeviceClass
    pci_host: str
    device_id: str
    compatible: bool


class GPUProperties(BaseModel):
    devices: list[GpuDevice]
    available_devices: list[GpuDevice]


class MachineUsage(BaseModel):
    cpu: CpuUsage
    mem: MemoryUsage
    disk: DiskUsage
    period: UsagePeriod
    properties: MachineProperties
    gpu: Optional[GPUProperties]
    active: bool = True


class MachineInfo(BaseModel):
    hash: str
    machine_usage: MachineUsage
    score: float
    name: str
    version: Optional[str]
    reward_address: str
    url: str

    @classmethod
    def from_unsanitized_input(
        cls,
        machine_usage: MachineUsage,
        score: float,
        name: str,
        version: Optional[str],
        reward_address: str,
        url: str,
        hash: str,
    ) -> "MachineInfo":
        """Create a MachineInfo instance from unsanitized input.

        User input from the account page or the API may contain malicious or unexpected data.
        This method ensures that the input is sanitized before creating a MachineInfo object.

        Args:
            machine_usage: MachineUsage object from the CRN API.
            score: Score of the CRN.
            name: Name of the CRN.
            version: Version of the CRN.
            reward_address: Reward address of the CRN.
            url: URL of the CRN.
        """
        node_name: str = _remove_ansi_escape(_escape_and_normalize(name))

        # The version field is optional, so we need to handle it separately
        raw_version: Optional[str] = version
        version = _remove_ansi_escape(_escape_and_normalize(raw_version)) if raw_version else None

        return cls(
            machine_usage=MachineUsage.model_validate(machine_usage),
            score=score,
            name=node_name,
            version=version,
            reward_address=reward_address,
            url=url,
            hash=hash,
        )


class CRNInfo(BaseModel):
    hash: ItemHash
    name: str
    owner: str
    url: str
    ccn_hash: Optional[str]
    status: Optional[str]
    version: Optional[str]
    score: float
    reward_address: str
    stream_reward_address: str
    machine_usage: Optional[MachineUsage]
    ipv6: bool
    qemu_support: bool
    confidential_computing: bool
    gpu_support: bool
    terms_and_conditions: Optional[str]
    compatible_available_gpus: Optional[list]

    @staticmethod
    def from_unsanitized_input(
        crn: dict[str, Any],
    ) -> "CRNInfo":
        payment_receiver_address = crn.get("payment_receiver_address")
        stream_reward_address = extract_valid_eth_address(payment_receiver_address) if payment_receiver_address else ""
        system_usage = crn.get("system_usage")
        machine_usage = MachineUsage.model_validate(system_usage) if system_usage else None
        ipv6_check = crn.get("ipv6_check")
        ipv6 = bool(ipv6_check and all(ipv6_check.values()))
        try:
            url = sanitize_url(crn["address"])
        except InvalidURL:
            url = ""
        return CRNInfo(
            hash=crn["hash"],
            name=crn["name"],
            owner=crn["owner"],
            url=url,
            version=crn["version"],
            ccn_hash=crn["parent"],
            status=crn["status"],
            score=crn["score"],
            reward_address=crn["reward"],
            stream_reward_address=stream_reward_address,
            machine_usage=machine_usage,
            ipv6=ipv6,
            qemu_support=bool(crn["qemu_support"]),
            confidential_computing=bool(crn["confidential_support"]),
            gpu_support=bool(crn["gpu_support"]),
            terms_and_conditions=crn["terms_and_conditions"],
            compatible_available_gpus=crn["compatible_available_gpus"],
        )

    @property
    def display_cpu(self) -> str:
        if self.machine_usage:
            return f"{self.machine_usage.cpu.count:>3}"
        return ""

    @property
    def display_ram(self) -> str:
        if self.machine_usage:
            return (
                f"{self.machine_usage.mem.available_kB / 1_000_000:>3.0f} / "
                f"{self.machine_usage.mem.total_kB / 1_000_000:>3.0f} GB"
            )
        return ""

    @property
    def display_hdd(self) -> str:
        if self.machine_usage:
            return (
                f"{self.machine_usage.disk.available_kB / 1_000_000:>4.0f} / "
                f"{self.machine_usage.disk.total_kB / 1_000_000:>4.0f} GB"
            )
        return ""

    @property
    async def terms_and_conditions_content(self) -> Optional[StoredContent]:
        if self.terms_and_conditions:
            return await download(self.terms_and_conditions, only_info=True, verbose=False)
        return None

    async def display_terms_and_conditions(self, auto_accept: bool = False) -> Optional[bool]:
        if self.terms_and_conditions:
            tac = await self.terms_and_conditions_content
            if tac:
                text = Text.assemble(
                    "The selected CRN requires you to accept the following conditions and terms of use:\n",
                    f"Filename: {tac.filename}\n" if tac.filename else "",
                    Text.from_markup(f"↳ [orange1]{tac.url}[/orange1]"),
                )
                console = Console()
                console.print(
                    Panel(text, title="Terms & Conditions", border_style="blue", expand=False, title_align="left")
                )

                if auto_accept:
                    echo("To proceed, enter “Yes I read and accept”: Yes I read and accept")
                    return True
                return Prompt.ask("To proceed, enter “Yes I read and accept”").lower() == "yes i read and accept"
        return None

    def display_crn_specs(self):
        console = Console()

        data = {
            "Hash": self.hash,
            "Name": self.name,
            "URL": self.url,
            "Version": self.version,
            "Score": self.score,
            "Stream Receiver": self.stream_reward_address,
            **(
                {
                    "Available Cores": self.display_cpu,
                    "Available RAM": self.display_ram,
                    "Available Disk": self.display_hdd,
                }
                if isinstance(self.machine_usage, MachineUsage)
                else {}
            ),
            "Support Qemu": self.qemu_support,
            "Support Confidential": self.confidential_computing,
            "Support GPU": self.gpu_support,
            **(
                {
                    "Terms & Conditions": self.terms_and_conditions,
                }
                if self.terms_and_conditions
                else {}
            ),
        }
        text = "\n".join(f"[orange3]{key}[/orange3]: {value}" for key, value in data.items())

        console.print(Panel(text, title="Selected CRN", border_style="bright_cyan", expand=False, title_align="left"))
