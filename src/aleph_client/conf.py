import os
from pathlib import Path
from shutil import which
from typing import Optional

from aleph_message.models.execution.environment import HypervisorType
from pydantic import BaseSettings, Field


class Settings(BaseSettings):
    CONFIG_HOME: Optional[str] = None

    # In case the user does not want to bother with handling private keys himself,
    # do an ugly and insecure write and read from disk to this file.
    PRIVATE_KEY_FILE: Path = Field(
        default=Path("ethereum.key"),
        description="Path to the private key used to sign messages",
    )

    PRIVATE_KEY_STRING: Optional[str] = None
    API_HOST: str = "https://api2.aleph.im"
    MAX_INLINE_SIZE: int = 50000
    API_UNIX_SOCKET: Optional[str] = None
    REMOTE_CRYPTO_HOST: Optional[str] = None
    REMOTE_CRYPTO_UNIX_SOCKET: Optional[str] = None
    ADDRESS_TO_USE: Optional[str] = None

    DEFAULT_CHANNEL: str = "ALEPH-CLOUDSOLUTIONS"
    DEFAULT_RUNTIME_ID: str = "63f07193e6ee9d207b7d1fcf8286f9aee34e6f12f101d2ec77c1229f92964696"
    DEBIAN_11_ROOTFS_ID: str = "887957042bb0e360da3485ed33175882ce72a70d79f1ba599400ff4802b7cee7"
    DEBIAN_12_ROOTFS_ID: str = "6e30de68c6cedfa6b45240c2b51e52495ac6fb1bd4b36457b3d5ca307594d595"
    UBUNTU_22_ROOTFS_ID: str = "77fef271aa6ff9825efa3186ca2e715d19e7108279b817201c69c34cedc74c27"
    DEBIAN_11_QEMU_ROOTFS_ID: str = "f7e68c568906b4ebcd3cd3c4bfdff96c489cd2a9ef73ba2d7503f244dfd578de"
    DEBIAN_12_QEMU_ROOTFS_ID: str = "b6ff5c3a8205d1ca4c7c3369300eeafff498b558f71b851aa2114afd0a532717"
    UBUNTU_22_QEMU_ROOTFS_ID: str = "4a0f62da42f4478544616519e6f5d58adb1096e069b392b151d47c3609492d0c"
    DEFAULT_ROOTFS_SIZE: int = 20_480
    DEFAULT_INSTANCE_MEMORY: int = 2_048
    DEFAULT_HYPERVISOR: HypervisorType = HypervisorType.qemu

    DEFAULT_VM_MEMORY: int = 128
    DEFAULT_VM_VCPUS: int = 1
    DEFAULT_VM_TIMEOUT: float = 30.0

    CODE_USES_SQUASHFS: bool = which("mksquashfs") is not None  # True if command exists

    VM_URL_PATH = "https://aleph.sh/vm/{hash}"
    VM_URL_HOST = "https://{hash_base32}.aleph.sh"

    DEFAULT_CONFIDENTIAL_FIRMWARE = "ba5bb13f3abca960b101a759be162b229e2b7e93ecad9d1307e54de887f177ff"
    DEFAULT_CONFIDENTIAL_FIRMWARE_HASH = "89b76b0e64fe9015084fbffdf8ac98185bafc688bfe7a0b398585c392d03c7ee"

    class Config:
        env_prefix = "ALEPH_"
        case_sensitive = False
        env_file = ".env"

    HTTP_REQUEST_TIMEOUT = 10.0


# Settings singleton
settings = Settings()

if settings.CONFIG_HOME is None:
    xdg_data_home = os.environ.get("XDG_DATA_HOME")
    if xdg_data_home is not None:
        os.environ["ALEPH_CONFIG_HOME"] = str(Path(xdg_data_home, ".aleph-im"))
    else:
        home = os.path.expanduser("~")
        os.environ["ALEPH_CONFIG_HOME"] = str(Path(home, ".aleph-im"))

    settings = Settings()

assert settings.CONFIG_HOME
if str(settings.PRIVATE_KEY_FILE) == "ethereum.key":
    settings.PRIVATE_KEY_FILE = Path(settings.CONFIG_HOME, "private-keys", "ethereum.key")
