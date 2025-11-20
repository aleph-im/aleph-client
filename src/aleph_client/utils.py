from __future__ import annotations

import asyncio
import inspect
import logging
import os
import re
import subprocess
import sys
import time
from asyncio import ensure_future
from functools import lru_cache, partial, wraps
from pathlib import Path
from shutil import make_archive
from typing import Optional, Union
from urllib.parse import ParseResult, urlparse
from zipfile import BadZipFile, ZipFile

import aiohttp
import hid
import typer
from aiohttp import ClientSession
from aleph.sdk.account import AccountTypes, _load_account
from aleph.sdk.conf import (
    AccountType,
    MainConfiguration,
    load_main_configuration,
    settings,
)
from aleph.sdk.types import GenericMessage
from aleph.sdk.wallets.ledger import LedgerETHAccount
from aleph_message.models import Chain
from aleph_message.models.base import MessageType
from aleph_message.models.execution.base import Encoding
from ledgereth.exceptions import LedgerError

logger = logging.getLogger(__name__)
LEDGER_VENDOR_ID = 0x2C97

try:
    import magic
except ImportError:
    logger.info("Could not import library 'magic', MIME type detection disabled")
    magic = None  # type:ignore


def try_open_zip(path: Path) -> None:
    """Try opening a zip to check if it is valid"""
    assert path.is_file()
    with open(path, "rb") as archive_file:
        with ZipFile(archive_file, "r") as archive:
            if not archive.namelist():
                msg = "No file in the archive."
                raise BadZipFile(msg)


def create_archive(path: Path) -> tuple[Path, Encoding]:
    """Create a zip archive from a directory"""
    if os.path.isdir(path):
        if settings.CODE_USES_SQUASHFS:
            logger.debug("Creating squashfs archive...")
            archive_path = Path(f"{path}.squashfs")
            subprocess.check_call(["/usr/bin/mksquashfs", path, archive_path, "-noappend"])
            assert archive_path.is_file()
            return archive_path, Encoding.squashfs
        else:
            logger.debug("Creating zip archive...")
            make_archive(str(path), "zip", path)
            archive_path = Path(f"{path}.zip")
            return archive_path, Encoding.zip
    elif os.path.isfile(path):
        if path.suffix == ".squashfs" or (magic and magic.from_file(path).startswith("Squashfs filesystem")):
            return path, Encoding.squashfs
        else:
            try_open_zip(Path(path))
            return path, Encoding.zip
    else:
        msg = "No file or directory to create the archive from"
        raise FileNotFoundError(msg)


def get_message_type_value(message_type: type[GenericMessage]) -> MessageType:
    """Returns the value of the 'type' field of a message type class."""
    type_literal = message_type.__annotations__["type"]
    return type_literal.__args__[0]  # Get the value from a Literal


class AsyncTyper(typer.Typer):
    @staticmethod
    def maybe_run_async(decorator, f):
        if inspect.iscoroutinefunction(f):

            @wraps(f)
            def runner(*args, **kwargs):
                return asyncio.run(f(*args, **kwargs))

            decorator(runner)
        else:
            decorator(f)
        return f

    def callback(self, *args, **kwargs):
        decorator = super().callback(*args, **kwargs)
        return partial(self.maybe_run_async, decorator)

    def command(self, *args, **kwargs):
        decorator = super().command(*args, **kwargs)
        return partial(self.maybe_run_async, decorator)


async def fetch_json(session: ClientSession, url: str) -> dict:
    async with session.get(url) as resp:
        resp.raise_for_status()
        return await resp.json()


def extract_valid_eth_address(address: str) -> str:
    if address:
        pattern = r"0x[a-fA-F0-9]{40}"
        match = re.search(pattern, address)
        if match:
            return match.group(0)
    return ""


async def list_unlinked_keys() -> tuple[list[Path], Optional[MainConfiguration]]:
    """
    List private key files that are not linked to any chain type and return the active MainConfiguration.

    Returns:
        - A tuple containing:
            - A list of unlinked private key files as Path objects.
            - The active MainConfiguration object (the single account in the config file).
    """
    config_home: Union[str, Path] = settings.CONFIG_HOME if settings.CONFIG_HOME else Path.home()
    private_key_dir = Path(config_home, "private-keys")

    if not private_key_dir.exists():
        return [], None

    all_private_key_files = list(private_key_dir.glob("*.key"))

    config: MainConfiguration | None = load_main_configuration(Path(settings.CONFIG_FILE))

    if not config:
        logger.warning("No config file found.")
        return all_private_key_files, None

    active_key_path = config.path

    unlinked_keys: list[Path] = [key_file for key_file in all_private_key_files if key_file != active_key_path]

    return unlinked_keys, config


# Some users had fun adding URLs that are obviously not CRNs.
# If you work for one of these companies, please send a large check to the Aleph team,
# and we may consider removing your domain from the blacklist. Or just use a subdomain.
FORBIDDEN_HOSTS = [
    "amazon.com",
    "apple.com",
    "facebook.com",
    "google.com",
    "google.es",
    "microsoft.com",
    "openai.com",
    "twitter.com",
    "x.com",
    "youtube.com",
]


def sanitize_url(url: str) -> str:
    """Ensure that the URL is valid and not obviously irrelevant.

    Args:
        url: URL to sanitize.
    Returns:
        Sanitized URL.
    """
    if not url:
        msg = "Empty URL"
        raise aiohttp.InvalidURL(msg)
    parsed_url: ParseResult = urlparse(url)
    if parsed_url.scheme not in ["http", "https"]:
        msg = f"Invalid URL scheme: {parsed_url.scheme}"
        raise aiohttp.InvalidURL(msg)
    if parsed_url.hostname in FORBIDDEN_HOSTS:
        logger.debug(
            f"Invalid URL {url} hostname {parsed_url.hostname} is in the forbidden host list "
            f"({', '.join(FORBIDDEN_HOSTS)})"
        )
        msg = "Invalid URL host"
        raise aiohttp.InvalidURL(msg)
    return url.strip("/")


def async_lru_cache(async_function):

    @lru_cache(maxsize=0 if "pytest" in sys.modules else 1)
    def cached_async_function(*args, **kwargs):
        return ensure_future(async_function(*args, **kwargs))

    return cached_async_function


def load_account(
    private_key_str: Optional[str], private_key_file: Optional[Path], chain: Optional[Chain] = None
) -> AccountTypes:
    """
    Two Case Possible
        - Account from private key
        - Hardware account (ledger)

    We first try to load configurations, if no configurations we fallback to private_key_str / private_key_file.
    """

    # 1st Check for configurations
    config_file_path = Path(settings.CONFIG_FILE)
    config = load_main_configuration(config_file_path)

    # If no config we try to load private_key_str / private_key_file
    if not config:
        logger.warning("No config detected fallback to private key")
        if private_key_str is not None:
            private_key_file = None

        elif private_key_file and not private_key_file.exists():
            logger.error("No account could be retrieved please use `aleph account create` or `aleph account configure`")
            raise typer.Exit(code=1)

    if not chain and config:
        chain = config.chain

    if config and config.type and config.type == AccountType.HARDWARE:
        try:
            wait_for_ledger_connection()
            return _load_account(None, None, chain=chain)
        except LedgerError as err:
            raise typer.Exit(code=1) from err
        except OSError as err:
            raise typer.Exit(code=1) from err
    else:
        return _load_account(private_key_str, private_key_file, chain=chain)


def list_ledger_dongles(unique_only: bool = True):
    """
    Enumerate Ledger devices, optionally filtering duplicates (multi-interface entries).
    Returns list of dicts with 'path' and 'product_string'.
    """
    devices = []
    seen_serials = set()

    for dev in hid.enumerate():
        if dev.get("vendor_id") != LEDGER_VENDOR_ID:
            continue

        product = dev.get("product_string") or "Ledger"
        path = dev.get("path")
        serial = dev.get("serial_number") or f"{dev.get('vendor_id')}:{dev.get('product_id')}"

        # Filter out duplicate interfaces
        if unique_only and serial in seen_serials:
            continue

        seen_serials.add(serial)
        devices.append(
            {
                "path": path,
                "product_string": product,
                "vendor_id": dev.get("vendor_id"),
                "product_id": dev.get("product_id"),
                "serial_number": serial,
            }
        )

    # Prefer :1.0 interface if multiple
    devices = [d for d in devices if not str(d["path"]).endswith(":1.1")]

    return devices


def get_ledger_name(device_info: dict) -> str:
    """
    Return a human-readable name for a Ledger dongle.
    Example: "Ledger Nano X (0001:0023)" or "Ledger (unknown)".
    """
    if not device_info:
        return "Unknown Ledger"

    name = device_info.get("product_string") or "Ledger"
    raw_path = device_info.get("path")
    if isinstance(raw_path, bytes):
        raw_path = raw_path.decode(errors="ignore")

    # derive a short, friendly ID
    short_id = None
    if raw_path:
        short_id = raw_path.split("#")[-1][:8] if "#" in raw_path else raw_path[-8:]
    return f"{name} ({short_id})" if short_id else name


def get_first_ledger_name() -> str:
    """Return the name of the first connected Ledger, or 'No Ledger found'."""
    devices = list_ledger_dongles()
    if not devices:
        return "No Ledger found"
    return get_ledger_name(devices[0])


def get_account_and_address(
    private_key: Optional[str],
    private_key_file: Optional[Path],
    address: Optional[str] = None,
    chain: Optional[Chain] = None,
) -> tuple[Optional[AccountTypes], Optional[str]]:
    """
    Gets the account and address based on configuration and provided parameters.

    This utility function handles the common pattern of loading an account and address
    from either a configuration file or private key/file, avoiding ledger connections
    when not needed.

    Args:
        private_key: Optional private key string
        private_key_file: Optional private key file path
        address: Optional address (will be returned if provided)
        chain: Optional chain for account loading

    Returns:
        A tuple of (account, address) where either or both may be None
    """
    config_file_path = Path(settings.CONFIG_FILE)
    config = load_main_configuration(config_file_path)
    account_type = config.type if config else None

    account = None

    # Avoid connecting to ledger
    if not account_type or account_type == AccountType.IMPORTED:
        account = load_account(private_key, private_key_file, chain=chain)
        if account and not address:
            address = account.get_address()
    elif not address and config and config.address:
        address = config.address

    return account, address


def wait_for_ledger_connection(poll_interval: float = 1.0) -> None:
    """
    Wait until a Ledger device is connected and ready.

    Uses HID to detect physical connection, then confirms communication
    by calling LedgerETHAccount.get_accounts(). Handles permission errors
    gracefully and allows the user to cancel (Ctrl+C).

    Parameters
    ----------
    poll_interval : float
        Seconds between checks (default: 1).
    """

    vendor_id = 0x2C97  # Ledger vendor ID

    # Check if ledger is already connected and ready
    try:
        accounts = LedgerETHAccount.get_accounts()
        if accounts:
            typer.secho("Ledger connected and ready!", fg=typer.colors.GREEN)
            return
    except Exception as e:
        # Continue with the normal flow if not ready
        logger.debug(f"Ledger not ready: {e}")

    typer.secho("\nPlease connect your Ledger device and unlock it.", fg=typer.colors.CYAN)
    typer.echo("   (Open the Ethereum app if required.)")
    typer.echo("   Press Ctrl+C to cancel.\n")

    # No longer using this variable, removed
    while True:
        try:
            # Detect via HID
            devices = hid.enumerate(vendor_id, 0)
            if not devices:
                typer.echo("Waiting for Ledger device connection...", err=True)
                time.sleep(poll_interval)
                continue

            # Try to communicate (device connected but may be locked)
            try:
                accounts = LedgerETHAccount.get_accounts()
                if accounts:
                    typer.secho("Ledger connected and ready!", fg=typer.colors.GREEN)
                    return
            except LedgerError:
                typer.echo("Ledger detected but locked or wrong app open.", err=True)
                time.sleep(poll_interval)
                continue
            except BaseException as e:
                typer.echo(f"Communication error with Ledger: {str(e)[:50]}... Retrying...", err=True)
                time.sleep(poll_interval)
                continue

        except OSError as err:
            # Typically means missing permissions or udev rules
            typer.secho(
                f"OS error while accessing Ledger ({err}).\n"
                "Please ensure you have proper USB permissions (udev rules).",
                fg=typer.colors.RED,
            )
            raise typer.Exit(1) from err
        except KeyboardInterrupt as err:
            typer.secho("\nCancelled by user.", fg=typer.colors.YELLOW)
            raise typer.Exit(1) from err

        time.sleep(poll_interval)
