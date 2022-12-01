from dataclasses import dataclass
from typing import Dict, NewType, Union
from enum import Enum
from shutil import which

class StorageDriverEnum(Enum):
    VFS = 1
    # OVERLAY2 = 2


@dataclass
class VFSSettings:
    optimize: bool = True # Keep only last layer and delete previous ones
    use_tarsplit: bool = which("tar-split") is not None and which("tar") is not None

DriverConf = NewType("DriverConf", VFSSettings) # Use Union to accomodate new features

drivers_conf: Dict[StorageDriverEnum, DriverConf] = {
    StorageDriverEnum.VFS: VFSSettings()
}


@dataclass
class StorageDriverSettings:
    kind: StorageDriverEnum
    conf: DriverConf

    def __init__(self, kind: StorageDriverEnum):
        self.kind = kind
        self.conf = drivers_conf[kind]


@dataclass
class DockerSettings:
    storage_driver: StorageDriverSettings
    populate: bool

docker_settings = DockerSettings(
    storage_driver=StorageDriverSettings(
        kind=StorageDriverEnum.VFS
    ),
    populate=False
)