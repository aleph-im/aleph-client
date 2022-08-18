import asyncio
import logging
from pathlib import Path
from typing import Optional, TypeVar, Type

from aleph_client.chains.common import get_fallback_private_key
from aleph_client.chains.ethereum import ETHAccount
from aleph_client.chains.remote import RemoteAccount
from aleph_client.conf import settings
from aleph_client.types import AccountFromPrivateKey

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=AccountFromPrivateKey)


def account_from_hex_string(private_key_str: str, account_type: Type[T]) -> T:
    if private_key_str.startswith("0x"):
        private_key_str = private_key_str[2:]
    return account_type(bytes.fromhex(private_key_str))


def account_from_file(private_key_path: Path, account_type: Type[T]) -> T:
    with open(private_key_path, "rb") as pk_fd:
        private_key: bytes = pk_fd.read()
    return account_type(private_key)


def _load_account(
    private_key_str: Optional[str] = None,
    private_key_path: Optional[Path] = None,
    account_type: Type[AccountFromPrivateKey] = ETHAccount,
) -> AccountFromPrivateKey:
    """Load private key from a string or a file.

    Only keys that accounts that can be initiated from a
    """

    assert not (
        private_key_str and private_key_path
    ), "Private key should be a string or a filepath, not both."

    if private_key_str:
        logger.debug("Using account from string")
        return account_from_hex_string(private_key_str, account_type)
    elif private_key_path and private_key_path.is_file():
        logger.debug("Using account from file")
        return account_from_file(private_key_path, account_type)
    elif settings.REMOTE_CRYPTO_HOST:
        logger.debug("Using remote account")
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(
            RemoteAccount.from_crypto_host(
                host=settings.REMOTE_CRYPTO_HOST,
                unix_socket=settings.REMOTE_CRYPTO_UNIX_SOCKET,
            )
        )
    else:
        new_private_key = get_fallback_private_key()
        account = account_type(private_key=new_private_key)
        logger.info(
            f"Generated fallback private key with address {account.get_address()}"
        )
        return account
