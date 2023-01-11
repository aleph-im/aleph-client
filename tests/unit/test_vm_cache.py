import pytest

from aleph_client.vm.cache import TestVmCache, sanitize_cache_key


@pytest.mark.asyncio
async def test_local_vm_cache():
    cache = TestVmCache()
    assert (await cache.get("doesnotexist")) is None
    assert len(await (cache.keys())) == 0
    key = "thisdoesexist"
    value = "yay, I exist!"
    await cache.set(key, value)
    cached_value = await cache.get(key)
    assert cached_value is not None
    assert cached_value.decode() == value
    assert (await cache.keys())[0] == key
    assert (await cache.keys("*exist"))[0] == key
    await cache.delete(key)
    assert (await cache.get(key)) is None
    assert len(await (cache.keys())) == 0


def test_sanitize_cache_keys():
    assert sanitize_cache_key("abc")
    assert sanitize_cache_key("abc123")
    assert sanitize_cache_key("abc_123")
    with pytest.raises(ValueError):
        sanitize_cache_key("abc-123")
    with pytest.raises(ValueError):
        sanitize_cache_key("abc!123")
    with pytest.raises(ValueError):
        assert sanitize_cache_key("*")
