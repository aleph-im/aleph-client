from __future__ import annotations

import logging
from ipaddress import IPv6Interface
from json import JSONDecodeError
from typing import Optional

from aiohttp import (
    ClientConnectorError,
    ClientResponseError,
    ClientSession,
    ClientTimeout,
    InvalidURL,
)
from aleph.sdk import AlephHttpClient
from aleph.sdk.conf import settings
from aleph.sdk.exceptions import ForgottenMessageError, MessageNotFoundError
from aleph.sdk.utils import safe_getattr
from aleph_message.models import InstanceMessage
from aleph_message.models.execution.base import PaymentType
from aleph_message.models.item_hash import ItemHash
from click import echo
from pydantic import ValidationError
from typer import Exit

from aleph_client.commands import help_strings
from aleph_client.commands.files import download
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
async def call_program_crn_list() -> Optional[dict]:
    """Call program to fetch the compute resource node list.

    Returns:
        dict: Dictionary containing the compute resource node list.
    """

    try:
        async with ClientSession(timeout=ClientTimeout(total=60)) as session:
            logger.debug("Fetching crn list...")
            async with session.get(crn_list_link) as resp:
                if resp.status != 200:
                    error = "Unable to fetch crn list from program"
                    raise Exception(error)
                return await resp.json()
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
    raise Exception(error)


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
        if gpu and not (crn.get("gpu_support") and crn.get("compatible_available_gpus")):
            continue
        try:
            crns.append(CRNInfo.from_unsanitized_input(crn))
        except ValidationError:
            logger.debug(f"Invalid CRN: {crn}")
            continue
    return crns


async def fetch_crn_info(crn_url: Optional[str] = None, crn_hash: Optional[str] = None) -> Optional[CRNInfo]:
    """Retrieve a compute resource node by URL.

    Args:
        crn_url (Optional[str]): URL of the compute resource node.
        crn_hash (Optional[str]): Hash of the compute resource node.
    Returns:
        Union[CRNInfo, None]: The compute resource node or None if not found.
    """

    crn_url = sanitize_url(crn_url)
    crn_list = await fetch_crn_list()
    for crn in crn_list:
        if crn.url == crn_url or crn.hash == crn_hash:
            return crn
    return None


async def fetch_vm_info(message: InstanceMessage) -> tuple[str, dict[str, str]]:
    """Fetches VM information given an instance message.

    Args:
        message: Instance message.
    Returns:
        VM information.
    """

    async with ClientSession() as session:
        chain = safe_getattr(message, "content.payment.chain.value")
        hold = safe_getattr(message, "content.payment.type.value")
        crn_hash = safe_getattr(message, "content.requirements.node.node_hash")
        created_at = safe_getattr(message, "content.time")

        is_hold = hold == PaymentType.hold.value
        firmware = safe_getattr(message, "content.environment.trusted_execution.firmware")
        is_confidential = firmware and len(firmware) == 64
        has_gpu = safe_getattr(message, "content.requirements.gpu")
        tac_hash = safe_getattr(message, "content.requirements.node.terms_and_conditions")

        info = {
            "crn_hash": str(crn_hash) if crn_hash else "",
            "created_at": str(created_at),
            "payment": str(hold),
            "chain": str(chain),
            "confidential": str(firmware) if is_confidential else "",
            "allocation_type": "",
            "ipv6_logs": "",
            "crn_url": "",
            "tac_hash": str(tac_hash) if tac_hash else "",
            "tac_url": "",
            "tac_accepted": "",
        }
        try:
            # Fetch from the scheduler API directly if no payment or no receiver (hold-tier non-confidential)
            if is_hold and not is_confidential and not has_gpu:
                try:
                    url = f"https://scheduler.api.aleph.cloud/api/v0/allocation/{message.item_hash}"
                    info["allocation_type"] = help_strings.ALLOCATION_AUTO
                    allocation = await fetch_json(session, url)
                    url = "https://scheduler.api.aleph.cloud/api/v0/nodes"
                    nodes = await fetch_json(session, url)
                    info["ipv6_logs"] = allocation["vm_ipv6"]
                    for node in nodes["nodes"]:
                        if node["ipv6"].split("::")[0] == ":".join(str(info["ipv6_logs"]).split(":")[:4]):
                            info["crn_url"] = sanitize_url(node["url"])
                            break
                except (ClientResponseError, ClientConnectorError) as e:
                    info["crn_url"] = help_strings.CRN_PENDING
                    info["ipv6_logs"] = help_strings.VM_SCHEDULED
                    logger.debug(f"Error while calling Scheduler API ({url}): {e}")
            else:
                # Fetch from the CRN program endpoint if PAYG-tier or confidential or GPU
                info["allocation_type"] = help_strings.ALLOCATION_MANUAL
                node_list = await fetch_crn_list()
                for node in node_list:
                    if node.hash == crn_hash:
                        info["crn_url"] = node.url
                        break
                if info["crn_url"]:
                    path = f"{info['crn_url']}{PATH_ABOUT_EXECUTIONS_LIST}"
                    executions = await fetch_json(session, path)
                    if message.item_hash in executions:
                        interface = IPv6Interface(executions[message.item_hash]["networking"]["ipv6"])
                        info["ipv6_logs"] = str(interface.ip + 1)
                else:
                    info["crn_url"] = help_strings.CRN_UNKNOWN
                if not info["ipv6_logs"]:
                    info["ipv6_logs"] = help_strings.VM_NOT_READY
                # Terms and conditions
                if tac_hash:
                    tac = await download(tac_hash, only_info=True, verbose=False)
                    tac_url = safe_getattr(tac, "url") or f"missing → {tac_hash}"
                    info.update({"tac_url": tac_url, "tac_accepted": "Yes"})
        except (ClientResponseError, ClientConnectorError) as e:
            info["ipv6_logs"] = f"Not available. Server error: {e}"
        return message.item_hash, info


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
        except MessageNotFoundError:
            echo("Instance does not exist on aleph.im")
        except ForgottenMessageError:
            echo("Instance has been deleted on aleph.im")
        if not message:
            raise Exit(code=1)
        _, info = await fetch_vm_info(message)
        is_valid = info["crn_url"] not in [help_strings.CRN_PENDING, help_strings.CRN_UNKNOWN]
        return str(info["crn_url"]) if is_valid else None


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
