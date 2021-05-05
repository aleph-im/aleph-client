import pytest
from aleph_client.asynchronous import get_messages


@pytest.mark.asyncio
async def test_get_messages():
    response = await get_messages(
        pagination=2,
    )

    assert response.keys() == {
        'messages',
        'pagination_page',
        'pagination_total',
        'pagination_per_page',
        'pagination_item'
    }

    messages = response['messages']
    assert set(messages[0].keys()).issuperset({
        '_id',
        'chain',
        'item_hash',
        'sender',
        'type',
        'channel',
        'confirmed',
        'content',
        'item_content',
        'item_type',
        'signature',
        'size',
        'time',
        # 'confirmations',
    })
