from __future__ import annotations

import json
import logging
import re
from base64 import b16decode, b32encode
from collections.abc import Mapping
from pathlib import Path
from typing import List, Optional, cast
from zipfile import BadZipFile

import aiohttp
import typer
from aleph.sdk import AlephHttpClient, AuthenticatedAlephHttpClient
from aleph.sdk.account import _load_account
from aleph.sdk.client.vm_client import VmClient
from aleph.sdk.conf import settings
from aleph.sdk.exceptions import ForgottenMessageError, MessageNotFoundError
from aleph.sdk.query.filters import MessageFilter
from aleph.sdk.types import AccountFromPrivateKey, StorageEnum
from aleph.sdk.utils import safe_getattr
from aleph_message.models import Chain, MessageType, ProgramMessage, StoreMessage
from aleph_message.models.execution.program import ProgramContent
from aleph_message.models.item_hash import ItemHash
from aleph_message.status import MessageStatus
from click import echo
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from aleph_client.commands import help_strings
from aleph_client.commands.utils import (
    filter_only_valid_messages,
    get_or_prompt_environment_variables,
    get_or_prompt_volumes,
    input_multiline,
    setup_logging,
    str_to_datetime,
    validated_prompt,
    yes_no_input,
)
from aleph_client.utils import AsyncTyper, create_archive, sanitize_url

logger = logging.getLogger(__name__)
app = AsyncTyper(no_args_is_help=True)


@app.command()
async def create(
    path: Path = typer.Argument(..., help=help_strings.PROGRAM_PATH),
    name: Optional[str] = typer.Option(None, help="Name for your program"),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    print_message: bool = typer.Option(False),
    verbose: bool = True,
    debug: bool = False,
) -> Optional[str]:
    """Deploy a website on aleph.im"""

    setup_logging(debug)

    path = path.absolute()


@app.command()
async def update(
    path: Path = typer.Argument(..., help=help_strings.PROGRAM_PATH),
    name: str = typer.Argument(..., help="Item hash to update"),
    private_key: Optional[str] = settings.PRIVATE_KEY_STRING,
    private_key_file: Optional[Path] = settings.PRIVATE_KEY_FILE,
    print_message: bool = typer.Option(False),
    verbose: bool = True,
    debug: bool = False,
):
    """Update a website on aleph.im"""

    setup_logging(debug)

    path = path.absolute()


@app.command()
async def delete(
    name: str = typer.Argument(..., help="Item hash to update"),
    reason: str = typer.Option("User deletion", help="Reason for deleting the website"),
    private_key: Optional[str] = settings.PRIVATE_KEY_STRING,
    private_key_file: Optional[Path] = settings.PRIVATE_KEY_FILE,
    print_message: bool = typer.Option(False),
    verbose: bool = True,
    debug: bool = False,
):
    """Delete a website on aleph.im"""

    setup_logging(debug)

    account = _load_account(private_key, private_key_file)


@app.command(name="list")
async def list_websites(
    address: Optional[str] = typer.Option(None, help="Owner address of the websites"),
    private_key: Optional[str] = typer.Option(settings.PRIVATE_KEY_STRING, help=help_strings.PRIVATE_KEY),
    private_key_file: Optional[Path] = typer.Option(settings.PRIVATE_KEY_FILE, help=help_strings.PRIVATE_KEY_FILE),
    json: bool = typer.Option(default=False, help="Print as json instead of rich table"),
    debug: bool = False,
):
    """List all websites associated to an account"""

    setup_logging(debug)

    if address is None:
        account = _load_account(private_key, private_key_file)
        address = account.get_address()


@app.command()
async def history(
    name: str = typer.Argument(..., help="Item hash to update"),
    restore: Optional[str] = None,
    prune: Optional[str] = None,
    private_key: Optional[str] = settings.PRIVATE_KEY_STRING,
    private_key_file: Optional[Path] = settings.PRIVATE_KEY_FILE,
    print_message: bool = typer.Option(False),
    verbose: bool = True,
    debug: bool = False,
):
    """List or prune previous versions of a website on aleph.im"""

    setup_logging(debug)
