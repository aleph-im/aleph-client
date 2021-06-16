from typing import Optional

from pydantic import BaseSettings


class Settings(BaseSettings):
    PRIVATE_KEY_FILE: Optional[str] = None
    PRIVATE_KEY_STRING: Optional[str] = None
    API_HOST: str = "https://api2.aleph.im"
    API_UNIX_SOCKET: Optional[str] = None
    REMOTE_CRYPTO_HOST: Optional[str] = None
    REMOTE_CRYPTO_UNIX_SOCKET: Optional[str] = None
    ADDRESS_TO_USE: Optional[str] = None

    DEFAULT_RUNTIME_ID: str = "4ea78b56da35b154feb27228c78cd80fa9a2db18854fbf08cf5bb69bb3f48fba"
    DEFAULT_VM_MEMORY: int = 128

    CODE_USES_SQUASHFS: bool = True

    class Config:
        env_prefix = "ALEPH_"
        case_sensitive = False
        env_file = '.env'


# Settings singleton
settings = Settings()
