from __future__ import annotations

import logging
from ipaddress import IPv6Interface
from json import JSONDecodeError
from typing import Optional

import aiohttp
from aleph.sdk import AlephHttpClient
from aleph.sdk.conf import settings
from aleph_message.models import InstanceMessage
from aleph_message.models.execution.base import PaymentType
from aleph_message.models.item_hash import ItemHash
from pydantic import ValidationError

from aleph_client.commands import help_strings
from aleph_client.commands.node import NodeInfo, _fetch_nodes
from aleph_client.commands.utils import safe_getattr
from aleph_client.models import MachineUsage
from aleph_client.utils import AsyncTyper, fetch_json, sanitize_url

logger = logging.getLogger(__name__)


PATH_STATUS_CONFIG = "/status/config"
PATH_ABOUT_USAGE_SYSTEM = "/about/usage/system"


async def fetch_crn_info(node_url: str) -> dict | None:
    """
    Fetches compute node usage information and version.

    Args:
        node_url: URL of the compute node.
    Returns:
        CRN information.
    """
    url = ""
    try:
        base_url: str = sanitize_url(node_url.rstrip("/"))
        timeout = aiohttp.ClientTimeout(total=settings.HTTP_REQUEST_TIMEOUT)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            info: dict
            url = base_url + PATH_STATUS_CONFIG
            async with session.get(url) as resp:
                resp.raise_for_status()
                info = await resp.json()
            url = base_url + PATH_ABOUT_USAGE_SYSTEM
            async with session.get(url) as resp:
                resp.raise_for_status()
                system: dict = await resp.json()
                info["machine_usage"] = MachineUsage.parse_obj(system)
            return info
    except aiohttp.InvalidURL as e:
        logger.debug(f"Invalid CRN URL: {url}: {e}")
    except TimeoutError as e:
        logger.debug(f"Timeout while fetching CRN: {url}: {e}")
    except aiohttp.ClientConnectionError as e:
        logger.debug(f"Error on CRN connection: {url}: {e}")
    except aiohttp.ClientResponseError as e:
        logger.debug(f"Error on CRN response: {url}: {e}")
    except JSONDecodeError as e:
        logger.debug(f"Error decoding CRN JSON: {url}: {e}")
    except ValidationError as e:
        logger.debug(f"Validation error when fetching CRN: {url}: {e}")
    except Exception as e:
        logger.debug(f"Unexpected error when fetching CRN: {url}: {e}")
    return None


async def fetch_vm_info(message: InstanceMessage, node_list: NodeInfo) -> tuple[str, dict[str, str]]:
    """
    Fetches VM information given an instance message and the node list.

    Args:
        message: Instance message.
        node_list: Node list.
    Returns:
        VM information.
    """
    async with aiohttp.ClientSession() as session:
        chain = safe_getattr(message, "content.payment.chain.value")
        hold = safe_getattr(message, "content.payment.type.value")
        crn_hash = safe_getattr(message, "content.requirements.node.node_hash")
        created_at = safe_getattr(message, "content.time")

        is_hold = hold == PaymentType.hold.value
        firmware = safe_getattr(message, "content.environment.trusted_execution.firmware")
        is_confidential = firmware and len(firmware) == 64
        has_gpu = safe_getattr(message, "content.requirements.gpu")

        info = dict(
            crn_hash=str(crn_hash) if crn_hash else "",
            created_at=str(created_at),
            payment=str(hold),
            chain=str(chain),
            confidential=str(firmware) if is_confidential else "",
            allocation_type="",
            ipv6_logs="",
            crn_url="",
        )
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
                            info["crn_url"] = node["url"].rstrip("/")
                            break
                except (aiohttp.ClientResponseError, aiohttp.ClientConnectorError) as e:
                    info["crn_url"] = help_strings.CRN_PENDING
                    info["ipv6_logs"] = help_strings.VM_SCHEDULED
                    logger.debug(f"Error while calling Scheduler API ({url}): {e}")
            else:
                # Fetch from the CRN API if PAYG-tier or confidential or GPU
                info["allocation_type"] = help_strings.ALLOCATION_MANUAL
                for node in node_list.nodes:
                    if node["hash"] == crn_hash:
                        info["crn_url"] = node["address"].rstrip("/")
                        break
                if info["crn_url"]:
                    path = f"{info['crn_url']}/about/executions/list"
                    executions = await fetch_json(session, path)
                    if message.item_hash in executions:
                        interface = IPv6Interface(executions[message.item_hash]["networking"]["ipv6"])
                        info["ipv6_logs"] = str(interface.ip + 1)
                else:
                    info["crn_url"] = help_strings.CRN_UNKNOWN
                if not info["ipv6_logs"]:
                    info["ipv6_logs"] = help_strings.VM_NOT_READY
        except (aiohttp.ClientResponseError, aiohttp.ClientConnectorError) as e:
            info["ipv6_logs"] = f"Not available. Server error: {e}"
        return message.item_hash, info


async def find_crn_of_vm(vm_id: str) -> Optional[str]:
    async with AlephHttpClient(api_server=settings.API_HOST) as client:
        message: InstanceMessage = await client.get_message(item_hash=ItemHash(vm_id), message_type=InstanceMessage)
        node_list: NodeInfo = await _fetch_nodes()
        _, info = await fetch_vm_info(message, node_list)
        is_valid = info["crn_url"] not in [help_strings.CRN_PENDING, help_strings.CRN_UNKNOWN]
        return str(info["crn_url"]) if is_valid else None
