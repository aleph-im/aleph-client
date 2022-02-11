import pytest

from aleph_client.asynchronous import (
    get_messages,
    fetch_aggregates,
    fetch_aggregate,
    _get_fallback_session,
)


@pytest.mark.asyncio
async def test_fetch_aggregate():
    _get_fallback_session.cache_clear()

    response = await fetch_aggregate(
        address="0xa1B3bb7d2332383D96b7796B908fB7f7F3c2Be10", key="corechannel"
    )
    assert response.keys() == {"nodes"}


@pytest.mark.asyncio
async def test_fetch_aggregates():
    _get_fallback_session.cache_clear()

    response = await fetch_aggregates(
        address="0xa1B3bb7d2332383D96b7796B908fB7f7F3c2Be10"
    )
    assert response.keys() == {"corechannel"}
    assert response["corechannel"].keys() == {"nodes"}


@pytest.mark.asyncio
async def test_get_posts():
    _get_fallback_session.cache_clear()

    response = await get_messages(
        pagination=2,
    )

    assert response.keys() == {
        "messages",
        "pagination_page",
        "pagination_total",
        "pagination_per_page",
        "pagination_item",
    }

    messages = response["messages"]
    assert set(messages[0].keys()).issuperset(
        {
            "_id",
            "chain",
            "item_hash",
            "sender",
            "type",
            "channel",
            "confirmed",
            "content",
            "item_content",
            "item_type",
            "signature",
            "size",
            "time",
            # 'confirmations',
        }
    )


@pytest.mark.asyncio
async def test_get_messages():
    _get_fallback_session.cache_clear()

    response = await get_messages(
        pagination=2,
    )

    assert response.keys() == {
        "messages",
        "pagination_page",
        "pagination_total",
        "pagination_per_page",
        "pagination_item",
    }

    messages = response["messages"]
    assert set(messages[0].keys()).issuperset(
        {
            "_id",
            "chain",
            "item_hash",
            "sender",
            "type",
            "channel",
            "confirmed",
            "content",
            "item_content",
            "item_type",
            "signature",
            "size",
            "time",
            # 'confirmations',
        }
    )
