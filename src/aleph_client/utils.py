from __future__ import annotations

import asyncio
import inspect
import logging
import os
import re
import subprocess
import sys
from asyncio import ensure_future
from functools import lru_cache, partial, wraps
from pathlib import Path
from shutil import make_archive
from typing import Optional, Union
from urllib.parse import ParseResult, urlparse
from zipfile import BadZipFile, ZipFile

import aiohttp
import typer
from aiohttp import ClientSession
from aleph.sdk.conf import MainConfiguration, load_main_configuration, settings
from aleph.sdk.types import GenericMessage
from aleph_message.models.base import MessageType
from aleph_message.models.execution.base import Encoding

logger = logging.getLogger(__name__)

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
