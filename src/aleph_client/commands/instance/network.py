from __future__ import annotations

import logging
from json import JSONDecodeError
from typing import Optional

from aiohttp import ClientConnectorError, ClientResponseError, ClientSession, InvalidURL
from aleph.sdk import AlephHttpClient
from aleph.sdk.client.services.crn import CRN, CrnList
from aleph.sdk.conf import settings
from aleph.sdk.exceptions import ForgottenMessageError, MessageNotFoundError
from aleph_message.models import InstanceMessage
from aleph_message.models.item_hash import ItemHash
from click import echo
from pydantic import ValidationError
from typer import Exit

from aleph_client.models import CRNInfo
from aleph_client.utils import async_lru_cache, fetch_json, sanitize_url

logger = logging.getLogger(__name__)

latest_crn_version_link = "https://api.github.com/repos/aleph-im/aleph-vm/releases/latest"

settings_link = (
    f"{sanitize_url(settings.API_HOST)}/api/v0/aggregates/0xFba561a84A537fCaa567bb7A2257e7142701ae2A.json?keys=settings"
)


@async_lru_cache
async def call_program_crn_list(only_active: bool = False) -> CrnList:
    """Call program to fetch the compute resource node list."""
    error = None
    try:
        async with AlephHttpClient() as client:
            return await client.crn.get_crns_list(only_active)
    except InvalidURL as e:
        error = f"Invalid URL: {settings.CRN_LIST_URL}: {e}"
    except TimeoutError as e:
        error = f"Timeout while fetching: {settings.CRN_LIST_URL}: {e}"
    except ClientConnectorError as e:
        error = f"Error on connection: {settings.CRN_LIST_URL}: {e}"
    except ClientResponseError as e:
        error = f"Error on response: {settings.CRN_LIST_URL}: {e}"
    except JSONDecodeError as e:
        error = f"Error when decoding JSON: {settings.CRN_LIST_URL}: {e}"
    except Exception as e:
        error = f"Unexpected error while fetching: {settings.CRN_LIST_URL}: {e}"
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
async def fetch_network_gpu(crn_list=None):
    async with AlephHttpClient(api_server=settings.API_HOST) as client:
        return await client.crn.fetch_gpu_on_network(crn_list=crn_list)


async def build_crn_info(crn_list: list[CRN]) -> list[CRNInfo]:
    """Build a list of CRNInfo from CRN List already filtered."""
    crns: list[CRNInfo] = []
    for crn in crn_list:
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
