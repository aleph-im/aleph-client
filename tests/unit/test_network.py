from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from aleph_client.commands.instance.network import fetch_crn_info
from aleph_client.commands.utils import found_gpus_by_model
from aleph_client.utils import sanitize_url

from .mocks import FAKE_CRN_BASIC_HASH, FAKE_CRN_BASIC_URL


def test_sanitize_url_removes_trailing_slash():
    """Test that sanitize_url removes trailing slashes."""
    assert sanitize_url("https://example.com/") == "https://example.com"
    assert sanitize_url("https://example.com///") == "https://example.com"


def test_sanitize_url_preserves_leading_slash():
    """Test that sanitize_url preserves leading slashes in path."""
    assert sanitize_url("https://example.com/path") == "https://example.com/path"
    assert sanitize_url("http://localhost:8000/api/v0") == "http://localhost:8000/api/v0"


def test_found_gpus_by_model_empty_list():
    """Test that found_gpus_by_model handles an empty list properly."""
    result = found_gpus_by_model([])
    assert result == {}


def test_found_gpus_by_model_no_gpus():
    """Test that found_gpus_by_model handles CRNs with no GPUs."""
    crn = MagicMock()
    crn.compatible_available_gpus = []

    result = found_gpus_by_model([crn])
    assert result == {}


def test_found_gpus_by_model_single_crn():
    """Test that found_gpus_by_model correctly processes GPUs from a single CRN."""
    crn = MagicMock()
    crn.compatible_available_gpus = [
        {"model": "RTX 3090", "device_name": "GPU1"},
        {"model": "RTX 3090", "device_name": "GPU2"},
        {"model": "A100", "device_name": "GPU3"},
    ]

    result = found_gpus_by_model([crn])

    expected = {
        "RTX 3090": {
            "GPU1": {"count": 1, "on_crns": 1},
            "GPU2": {"count": 1, "on_crns": 1},
        },
        "A100": {
            "GPU3": {"count": 1, "on_crns": 1},
        },
    }

    assert result == expected


def test_found_gpus_by_model_multiple_crns():
    """Test that found_gpus_by_model correctly aggregates GPUs across multiple CRNs."""
    crn1 = MagicMock()
    crn1.compatible_available_gpus = [
        {"model": "RTX 3090", "device_name": "GPU1"},
        {"model": "A100", "device_name": "GPU3"},
    ]

    crn2 = MagicMock()
    crn2.compatible_available_gpus = [
        {"model": "RTX 3090", "device_name": "GPU1"},
        {"model": "RTX 4090", "device_name": "GPU4"},
    ]

    result = found_gpus_by_model([crn1, crn2])

    expected = {
        "RTX 3090": {
            "GPU1": {"count": 2, "on_crns": 2},
        },
        "A100": {
            "GPU3": {"count": 1, "on_crns": 1},
        },
        "RTX 4090": {
            "GPU4": {"count": 1, "on_crns": 1},
        },
    }

    assert result == expected


@pytest.mark.asyncio
async def test_fetch_crn_info_by_url(mock_crn_list):
    """Test fetch_crn_info with URL parameter."""
    # Test with URL
    result = await fetch_crn_info(mock_crn_list, crn_url=FAKE_CRN_BASIC_URL)
    assert result is not None
    assert result.url == FAKE_CRN_BASIC_URL
    assert result.hash == FAKE_CRN_BASIC_HASH

    # Test with URL that has trailing slash (should be sanitized)
    result = await fetch_crn_info(mock_crn_list, crn_url=f"{FAKE_CRN_BASIC_URL}/")
    assert result is not None
    assert result.url == FAKE_CRN_BASIC_URL

    # Test with non-existent URL
    result = await fetch_crn_info(mock_crn_list, crn_url="https://nonexistent.com")
    assert result is None


@pytest.mark.asyncio
async def test_fetch_crn_info_by_hash(mock_crn_list):
    """Test fetch_crn_info with hash parameter."""
    # Test with hash
    result = await fetch_crn_info(mock_crn_list, crn_hash=FAKE_CRN_BASIC_HASH)
    assert result is not None
    assert result.hash == FAKE_CRN_BASIC_HASH

    # Test with non-existent hash
    result = await fetch_crn_info(mock_crn_list, crn_hash="nonexistent_hash")
    assert result is None
