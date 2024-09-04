from __future__ import annotations

import logging
from ipaddress import IPv6Interface
from json import JSONDecodeError
from typing import Optional
from urllib.parse import ParseResult, urlparse

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
from aleph_client.utils import fetch_json

logger = logging.getLogger(__name__)

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

PATH_STATUS_CONFIG = "/status/config"
PATH_ABOUT_USAGE_SYSTEM = "/about/usage/system"


def sanitize_url(url: str) -> str:
    """Ensure that the URL is valid and not obviously irrelevant.

    Args:
        url: URL to sanitize.
    Returns:
        Sanitized URL.
    """
    if not url:
        raise aiohttp.InvalidURL("Empty URL")
    parsed_url: ParseResult = urlparse(url)
    if parsed_url.scheme not in ["http", "https"]:
        raise aiohttp.InvalidURL(f"Invalid URL scheme: {parsed_url.scheme}")
    if parsed_url.hostname in FORBIDDEN_HOSTS:
        logger.debug(
            f"Invalid URL {url} hostname {parsed_url.hostname} is in the forbidden host list "
            f"({', '.join(FORBIDDEN_HOSTS)})"
        )
        raise aiohttp.InvalidURL("Invalid URL host")
    return url


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


async def fetch_vm_info(message: InstanceMessage, node_list: NodeInfo) -> tuple[str, dict[str, object]]:
    """
    Fetches VM information given an instance message and the node list.

    Args:
        message: Instance message.
        node_list: Node list.
    Returns:
        VM information.
    """
    async with aiohttp.ClientSession() as session:
        hold = not message.content.payment or message.content.payment.type == PaymentType["hold"]
        crn_hash = safe_getattr(message, "content.requirements.node.node_hash")
        firmware = safe_getattr(message, "content.environment.trusted_execution.firmware")
        confidential = firmware and len(firmware) == 64
        info = dict(
            crn_hash=str(crn_hash) if crn_hash else "",
            payment="hold\t   " if hold else str(safe_getattr(message, "content.payment.type.value")),
            chain="Any" if hold else str(safe_getattr(message, "content.payment.chain.value")),
            confidential=confidential,
            allocation_type="",
            ipv6_logs="",
            crn_url="",
        )
        try:
            # Fetch from the scheduler API directly if no payment or no receiver (hold-tier non-confidential)
            if hold and not confidential:
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
                    return message.item_hash, info
                except (aiohttp.ClientResponseError, aiohttp.ClientConnectorError) as e:
                    info["ipv6_logs"] = help_strings.VM_SCHEDULED
                    info["crn_url"] = help_strings.CRN_PENDING
                    logger.debug(f"Error while calling Scheduler API ({url}): {e}")
            else:
                # Fetch from the CRN API if PAYG-tier or confidential
                info["allocation_type"] = help_strings.ALLOCATION_MANUAL
                for node in node_list.nodes:
                    if node["hash"] == safe_getattr(message, "content.requirements.node.node_hash"):
                        info["crn_url"] = node["address"].rstrip("/")
                        path = f"{node['address'].rstrip('/')}/about/executions/list"
                        executions = await fetch_json(session, path)
                        if message.item_hash in executions:
                            interface = IPv6Interface(executions[message.item_hash]["networking"]["ipv6"])
                            info["ipv6_logs"] = str(interface.ip + 1)
                            return message.item_hash, info
                info["ipv6_logs"] = help_strings.VM_NOT_READY if confidential else help_strings.VM_NOT_AVAILABLE_YET
        except (aiohttp.ClientResponseError, aiohttp.ClientConnectorError) as e:
            info["ipv6_logs"] = f"Not available. Server error: {e}"
        return message.item_hash, info


async def find_crn_of_vm(vm_id: str) -> Optional[str]:
    async with AlephHttpClient(api_server=settings.API_HOST) as client:
        message: InstanceMessage = await client.get_message(item_hash=ItemHash(vm_id), message_type=InstanceMessage)
        node_list: NodeInfo = await _fetch_nodes()
        _, info = await fetch_vm_info(message, node_list)
        is_valid = info["crn_url"] and info["crn_url"] != help_strings.CRN_PENDING
        return str(info["crn_url"]) if is_valid else None
