from typing import Optional

from pydantic import BaseSettings


class Settings(BaseSettings):
    PRIVATE_KEY_FILE: Optional[str] = None
    PRIVATE_KEY_STRING: Optional[str] = None
    API_HOST: str = "https://api1.aleph.im"
    API_UNIX_SOCKET: Optional[str] = None
    REMOTE_CRYPTO_HOST: Optional[str] = None
    REMOTE_CRYPTO_UNIX_SOCKET: Optional[str] = None
    ADDRESS_TO_USE: Optional[str] = None

    DEFAULT_RUNTIME_ID: str = "2e42d027a072042f91d8dd39999c8b4a684aeeda475712f2136e55f54a898fc5"
    DEFAULT_VM_MEMORY: int = 128

    class Config:
        env_prefix = "ALEPH_"
        case_sensitive = False
        env_file = '.env'


# Settings singleton
settings = Settings()
