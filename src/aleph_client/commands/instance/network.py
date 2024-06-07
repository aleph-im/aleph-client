import asyncio
import logging
import re
from json import JSONDecodeError
from typing import List, Literal, Optional, Tuple, Union

import aiohttp
from aiohttp import InvalidURL
from multidict import CIMultiDictProxy
from pydantic import ValidationError
from urllib3.util import Url, parse_url

from aleph_client.commands.node import NodeInfo
from aleph_client.conf import settings
from aleph_client.models import MachineInfo, MachineUsage

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
    "youtube.com",
]

# A queue is used to pass the machine info from the coroutines that fetch it to the
# coroutine in charge of updating the table and progress bar.
# Invalid URLs are represented as None, and the end of the queue is marked with "END_OF_QUEUE".
MachineInfoQueue = asyncio.Queue[Union[MachineInfo, None, Literal["END_OF_QUEUE"]]]


def get_version(headers: CIMultiDictProxy[str]) -> Optional[str]:
    """Extracts the version of the CRN from the headers of the response.

    Args:
        headers: aiohttp response headers.
    Returns:
        Version of the CRN if found, None otherwise.
    """
    if "Server" in headers:
        for server in headers.getall("Server"):
            version_match: List[str] = re.findall(r"^aleph-vm/(.*)$", server)
            # Return the first match
            if version_match and version_match[0]:
                return version_match[0]
    return None


async def fetch_crn_info(node_url: str) -> Tuple[Optional[MachineUsage], Optional[str]]:
    """
    Fetches compute node usage information and version.

    Args:
        node_url: URL of the compute node.
    Returns:
        Machine usage information and version.
    """
    # Remove trailing slashes to avoid having // in the URL.
    url: str = node_url.rstrip("/") + "/about/usage/system"
    timeout = aiohttp.ClientTimeout(total=settings.HTTP_REQUEST_TIMEOUT)
    try:
        # A new session is created for each request since they each target a different host.
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as resp:
                resp.raise_for_status()
                data_raw: dict = await resp.json()
                version = get_version(resp.headers)
                return MachineUsage.parse_obj(data_raw), version
    except TimeoutError:
        logger.debug(f"Timeout while fetching: {url}")
    except aiohttp.ClientConnectionError as e:
        logger.debug(f"Error on connection: {url}, {e}")
    except aiohttp.ClientResponseError:
        logger.debug(f"Error on response: {url}")
    except JSONDecodeError:
        logger.debug(f"Error decoding JSON: {url}")
    except ValidationError as e:
        logger.debug(f"Validation error when fetching: {url}: {e}")
    except InvalidURL as e:
        logger.debug(f"Invalid URL: {url}: {e}")
    return None, None


def sanitize_url(url: str) -> str:
    """Ensure that the URL is valid and not obviously irrelevant.

    Args:
        url: URL to sanitize.
    Returns:
        Sanitized URL.
    """
    if not url:
        raise InvalidURL("Empty URL")

    # Use urllib3 to parse the URL.
    # This should raise the same InvalidURL exception if the URL is invalid.
    parsed_url: Url = parse_url(url)

    if parsed_url.scheme not in ["http", "https"]:
        raise InvalidURL(f"Invalid URL scheme: {parsed_url.scheme}")

    if parsed_url.hostname in FORBIDDEN_HOSTS:
        raise InvalidURL("Invalid URL host")
    return url


async def fetch_crn_info_in_queue(node: dict, queue: MachineInfoQueue) -> None:
    """Fetch the resource usage from a CRN and put it in the queue

    Args:
        node: Information about the CRN from the 'corechannel' aggregate.
        queue: Queue used to update the table live.
    """
    # Skip nodes without an address or with an invalid address
    try:
        node_url = sanitize_url(node["address"])
    except InvalidURL:
        logger.info(f"Invalid URL: {node['address']}")
        await queue.put(None)
        return

    # Skip nodes without a reward address
    if not node["stream_reward"]:
        await queue.put(None)
        return

    # Fetch the machine usage and version from its HTTP API
    machine_usage, version = await fetch_crn_info(node_url)

    if not machine_usage:
        await queue.put(None)
        return

    await queue.put(
        MachineInfo.from_unsanitized_input(
            machine_usage=machine_usage,
            score=node["score"],
            name=node["name"],
            version=version,
            reward_address=node["stream_reward"],
            url=node["address"],
        )
    )


async def fetch_and_queue_crn_info(
    node_info: NodeInfo,
    queue: MachineInfoQueue,
):
    """Fetch the resource usage of all CRNs in the node_info asynchronously
    and put them in the queue.

    Fetches the resource usage and version of each node in parallel using a separate coroutine.

    Args:
        node_info: Information about all CRNs from the 'corechannel' aggregate.
        queue: Queue used to update the table live.
    """
    coroutines = [fetch_crn_info_in_queue(node, queue) for node in node_info.nodes]
    await asyncio.gather(*coroutines)
    await queue.put("END_OF_QUEUE")
