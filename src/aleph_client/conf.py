from pathlib import Path
from shutil import which
from typing import Optional

from pydantic import BaseSettings, Field
import os


class Settings(BaseSettings):
    ALEPH_IM_HOME: Optional[str] = None

    # In case the user does not want to bother with handling private keys himself,
    # do an ugly and insecure write and read from disk to this file.
    @property
    def PRIVATE_KEY_FILE(self) -> Path:
        """
        Path to the private key used to sign messages
        """
        return os.path.join(self.ALEPH_IM_HOME, "private-keys", "device.key")

    PRIVATE_KEY_STRING: Optional[str] = None
    API_HOST: str = "https://api2.aleph.im"
    MAX_INLINE_SIZE: int = 50000
    API_UNIX_SOCKET: Optional[str] = None
    REMOTE_CRYPTO_HOST: Optional[str] = None
    REMOTE_CRYPTO_UNIX_SOCKET: Optional[str] = None
    ADDRESS_TO_USE: Optional[str] = None

    DEFAULT_CHANNEL: str = "TEST"
    DEFAULT_RUNTIME_ID: str = (
        "bd79839bf96e595a06da5ac0b6ba51dea6f7e2591bb913deccded04d831d29f4"
    )
    DEFAULT_VM_MEMORY: int = 128
    DEFAULT_VM_VCPUS: int = 1
    DEFAULT_VM_TIMEOUT: float = 30.0

    CODE_USES_SQUASHFS: bool = which("mksquashfs") is not None  # True if command exists

    VM_URL_PATH = "https://aleph.sh/vm/{hash}"
    VM_URL_HOST = "https://{hash_base32}.aleph.sh"

    class Config:
        env_prefix = "ALEPH_"
        case_sensitive = False
        env_file = ".env"

# Settings singleton
settings = Settings()

if settings.ALEPH_IM_HOME is None:
    if os.environ.get("ALEPH_IM_HOME") is not None:
        os.environ["ALEPH_ALEPH_IM_HOME"] = os.environ.get("ALEPH_IM_HOME")
    else:
        xdg_data_home = os.environ.get("XDG_DATA_HOME")
        if xdg_data_home is not None:
            os.environ["ALEPH_ALEPH_IM_HOME"] = os.path.join(xdg_data_home, ".aleph-im")
        else:
            home = os.path.expanduser("~")
            os.environ["ALEPH_ALEPH_IM_HOME"] = os.path.join(home, ".aleph-im")

    settings = Settings()
