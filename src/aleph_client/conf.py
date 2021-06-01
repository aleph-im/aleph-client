from typing import Optional

from pydantic import BaseSettings


class Settings(BaseSettings):
    PRIVATE_KEY_FILE: Optional[str] = None
    PRIVATE_KEY_STRING: Optional[str] = None
    API_HOST: str = "https://api1.aleph.im"
    API_UNIX_SOCKET: Optional[str] = None
    REMOTE_CRYPTO_HOST: Optional[str] = None
    REMOTE_CRYPTO_UNIX_SOCKET: Optional[str] = None

    class Config:
        env_prefix = "ALEPH_"
        case_sensitive = False
        env_file = '.env'


# Settings singleton
settings = Settings()
