from __future__ import annotations

from pathlib import Path

import pytest

from aleph_client.commands.website import create, delete, history, list_websites, update


@pytest.mark.asyncio
async def test_create_website():
    async def run_create_website():
        await create(
            name="test_website",
            path=Path("/fake/website"),
        )

    await run_create_website()


@pytest.mark.asyncio
async def test_update_website():
    async def run_update_website():
        await update(
            name="test_website",
            path=Path("/fake/website"),
        )

    await run_update_website()


@pytest.mark.asyncio
async def test_delete_website():
    async def run_delete_website():
        await delete(
            name="-",
            reason="Test deletion",
        )

    await run_delete_website()


@pytest.mark.asyncio
async def test_list_websites():
    async def run_list_websites():
        await list_websites()

    await run_list_websites()


@pytest.mark.asyncio
async def test_website_history():
    async def run_website_history():
        await history(
            name="test_website",
        )

    await run_website_history()
