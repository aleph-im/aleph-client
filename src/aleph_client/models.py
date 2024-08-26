from datetime import datetime
from typing import Optional

from aleph_message.models import ItemHash
from aleph_message.models.execution.environment import CpuProperties
from pydantic import BaseModel
from typer import echo

from aleph_client.commands.node import _escape_and_normalize, _remove_ansi_escape


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


class MachineUsage(BaseModel):
    cpu: CpuUsage
    mem: MemoryUsage
    disk: DiskUsage
    period: UsagePeriod
    properties: MachineProperties
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
            machine_usage=MachineUsage.parse_obj(machine_usage),
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
    url: str
    version: Optional[str]
    score: float
    stream_reward_address: str
    machine_usage: Optional[MachineUsage]
    qemu_support: Optional[bool]
    confidential_computing: Optional[bool]

    @property
    def display_cpu(self) -> str:
        if self.machine_usage:
            return f"{self.machine_usage.cpu.count:>3}"
        return ""

    @property
    def display_ram(self) -> str:
        if self.machine_usage:
            return f"{self.machine_usage.mem.available_kB / 1_000_000:>3.0f} / {self.machine_usage.mem.total_kB / 1_000_000:>3.0f} GB"
        return ""

    @property
    def display_hdd(self) -> str:
        if self.machine_usage:
            return f"{self.machine_usage.disk.available_kB / 1_000_000:>4.0f} / {self.machine_usage.disk.total_kB / 1_000_000:>4.0f} GB"
        return ""

    def display_crn_specs(self):
        echo(f"Hash: {self.hash}")
        echo(f"Name: {self.name}")
        echo(f"URL: {self.url}")
        echo(f"Version: {self.version}")
        echo(f"Score: {self.score}")
        echo(f"Stream receiver: {self.stream_reward_address}")
        if isinstance(self.machine_usage, MachineUsage):
            echo(f"Available Cores: {self.display_cpu}")
            echo(f"Available RAM: {self.display_ram}")
            echo(f"Available Disk: {self.display_hdd}")
        echo(f"Support Qemu: {self.qemu_support}")
        echo(f"Support Confidential: {self.confidential_computing}")
