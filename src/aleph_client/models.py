from datetime import datetime
from typing import Optional

from aleph_message.models.execution.environment import CpuProperties
from pydantic import BaseModel

# This is a copy from aleph-vm


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
    system_info: MachineUsage
    score: str
    name: str
    version: Optional[str]
    reward_address: str
    address: str
