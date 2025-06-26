from __future__ import annotations

import logging
from json import JSONDecodeError
from typing import Optional

from aiohttp import ClientConnectorError, ClientResponseError, ClientSession, InvalidURL
from aleph.sdk import AlephHttpClient
from aleph.sdk.conf import settings
from aleph.sdk.exceptions import ForgottenMessageError, MessageNotFoundError
from aleph_message.models import InstanceMessage
from aleph_message.models.item_hash import ItemHash
from click import echo
from pydantic import ValidationError
from typer import Exit

from aleph_client.models import CRNInfo
from aleph_client.utils import (
    async_lru_cache,
    extract_valid_eth_address,
    fetch_json,
    sanitize_url,
)

logger = logging.getLogger(__name__)

latest_crn_version_link = "https://api.github.com/repos/aleph-im/aleph-vm/releases/latest"

settings_link = (
    f"{sanitize_url(settings.API_HOST)}"
    "/api/v0/aggregates/0xFba561a84A537fCaa567bb7A2257e7142701ae2A.json?keys=settings"
)

crn_list_link = (
    f"{sanitize_url(settings.CRN_URL_FOR_PROGRAMS)}"
    "/vm/bec08b08bb9f9685880f3aeb9c1533951ad56abef2a39c97f5a93683bdaa5e30/crns.json"
)

PATH_ABOUT_EXECUTIONS_LIST = "/about/executions/list"


@async_lru_cache
async def call_program_crn_list() -> dict:
    """Call program to fetch the compute resource node list."""
    error = None
    try:
        async with AlephHttpClient() as client:
            return await client.crn.get_crns_list(False)
    except InvalidURL as e:
        error = f"Invalid URL: {crn_list_link}: {e}"
    except TimeoutError as e:
        error = f"Timeout while fetching: {crn_list_link}: {e}"
    except ClientConnectorError as e:
        error = f"Error on connection: {crn_list_link}: {e}"
    except ClientResponseError as e:
        error = f"Error on response: {crn_list_link}: {e}"
    except JSONDecodeError as e:
        error = f"Error when decoding JSON: {crn_list_link}: {e}"
    except Exception as e:
        error = f"Unexpected error while fetching: {crn_list_link}: {e}"
    raise RuntimeError(error)


@async_lru_cache
async def fetch_latest_crn_version() -> str:
    """Fetch the latest crn version.

    Returns:
        str: Latest crn version as x.x.x.
    """

    async with ClientSession() as session:
        try:
            data = await fetch_json(session, latest_crn_version_link)
            version = data.get("tag_name")
            if not version:
                msg = "No tag_name found in GitHub release data"
                raise ValueError(msg)
            return version
        except Exception as e:
            logger.error(f"Error while fetching latest crn version: {e}")
            raise Exit(code=1) from e


@async_lru_cache
async def fetch_crn_list(
    latest_crn_version: bool = False,
    ipv6: bool = False,
    stream_address: bool = False,
    confidential: bool = False,
    gpu: bool = False,
) -> list[CRNInfo]:
    """Fetch compute resource node list, unfiltered by default.

    Args:
        latest_crn_version (bool): Filter by latest crn version.
        ipv6 (bool): Filter invalid IPv6 configuration.
        stream_address (bool): Filter invalid payment receiver address.
        confidential (bool): Filter by confidential computing support.
        gpu (bool): Filter by GPU support.
    Returns:
        list[CRNInfo]: List of compute resource nodes.
    """

    data = await call_program_crn_list()
    current_crn_version = await fetch_latest_crn_version()
    crns = []
    for crn in data.get("crns"):
        gpu_support = crn.get("gpu_support")
        available_gpu = crn.get("compatible_available_gpus")
        if latest_crn_version and (crn.get("version") or "0.0.0") < current_crn_version:
            continue
        if ipv6:
            ipv6_check = crn.get("ipv6_check")
            if not ipv6_check or not all(ipv6_check.values()):
                continue
        if stream_address and not extract_valid_eth_address(crn.get("payment_receiver_address") or ""):
            continue
        if confidential and not crn.get("confidential_support"):
            continue
        if gpu and (not gpu_support or not available_gpu):
            continue
        try:
            crns.append(CRNInfo.from_unsanitized_input(crn))
        except ValidationError:
            logger.debug(f"Invalid CRN: {crn}")
            continue
    return crns


async def fetch_crn_info(
    crn_list: list, crn_url: Optional[str] = None, crn_hash: Optional[str] = None
) -> Optional[CRNInfo]:
    """Retrieve a compute resource node by URL.

    Args:
        crn_list (list): List of compute resource nodes.
        crn_url (Optional[str]): URL of the compute resource node.
        crn_hash (Optional[str]): Hash of the compute resource node.
    Returns:
        Union[CRNInfo, None]: The compute resource node or None if not found.
    """
    if crn_url:
        crn_url = sanitize_url(crn_url)
    for crn in crn_list:
        crn_address = crn.get("address", None)
        if crn_hash and crn.get("hash", None) == crn_hash:
            return CRNInfo.from_unsanitized_input(crn)
        if crn_url and crn_address:
            try:
                if sanitize_url(crn_address) == crn_url:
                    return CRNInfo.from_unsanitized_input(crn)
            except Exception as e:
                logger.error(e)
                continue
    return None


async def find_crn_of_vm(vm_id: str) -> Optional[str]:
    """Finds the CRN where the VM is running given its item hash.

    Args:
        vm_id (str): Item hash of the VM.
    Returns:
        str: CRN url or None if not found.
    """

    async with AlephHttpClient(api_server=settings.API_HOST) as client:
        message: Optional[InstanceMessage] = None
        try:
            message = await client.get_message(item_hash=ItemHash(vm_id), message_type=InstanceMessage)
            if not message:
                raise Exit(code=1)

            allocations = await client.instance.get_instances_allocations(messages_list=[message])
            # Make sure to await the result if it's a coroutine
            if hasattr(allocations, "__await__"):
                allocations = await allocations

            if not allocations:
                return None

            info = allocations.root.get(vm_id, None)
            if not info:
                return None

            # Check by type name, which will work with mocks in tests
            if getattr(info.__class__, "__name__", "") == "InstanceManual":
                return info.crn_url
            else:
                # This is InstanceWithScheduler
                return info.allocations.node.url
        except MessageNotFoundError:
            echo("Instance does not exist on aleph.im")
        except ForgottenMessageError:
            echo("Instance has been deleted on aleph.im")

        return None


@async_lru_cache
async def fetch_settings() -> dict:
    """Fetch the settings from aggregate for flows and gpu instances.

    Returns:
        dict: Dictionary containing the settings.
    """

    async with ClientSession() as session:
        try:
            data = await fetch_json(session, settings_link)
            return data.get("data", {}).get("settings")
        except Exception as e:
            logger.error(f"Error while fetching settings: {e}")
            raise Exit(code=1) from e
