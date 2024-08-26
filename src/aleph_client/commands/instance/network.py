from __future__ import annotations

import logging
from json import JSONDecodeError
from typing import Optional
from urllib.parse import ParseResult, urlparse

import aiohttp
from aiohttp import InvalidURL
from pydantic import ValidationError

from aleph_client.conf import settings
from aleph_client.models import MachineUsage

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


async def fetch_crn_info(node_url: str) -> Optional[dict]:
    """
    Fetches compute node usage information and version.

    Args:
        node_url: URL of the compute node.
    Returns:
        All CRN information.
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
    except InvalidURL as e:
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


def sanitize_url(url: str) -> str:
    """Ensure that the URL is valid and not obviously irrelevant.

    Args:
        url: URL to sanitize.
    Returns:
        Sanitized URL.
    """
    if not url:
        raise InvalidURL("Empty URL")
    parsed_url: ParseResult = urlparse(url)
    if parsed_url.scheme not in ["http", "https"]:
        raise InvalidURL(f"Invalid URL scheme: {parsed_url.scheme}")
    if parsed_url.hostname in FORBIDDEN_HOSTS:
        logger.debug(
            f"Invalid URL {url} hostname {parsed_url.hostname} is in the forbidden host list "
            f"({', '.join(FORBIDDEN_HOSTS)})"
        )
        raise InvalidURL("Invalid URL host")
    return url
