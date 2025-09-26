from __future__ import annotations

import pytest

from aleph_client.commands.instance.network import fetch_crn_info
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
