import pytest

from aleph_client.vm.cache import TestVmCache, BaseVmCache


async def test_cache(cache: BaseVmCache):
    assert (await cache.get("doesnotexist")) is None
    assert len(await (cache.keys())) == 0
    key = "thisdoesexist"
    value = "yay, I exist!"
    await cache.set(key, value)
    assert (await cache.get(key)).decode() == value
    assert (await cache.keys())[0] == key
    assert (await cache.keys("*exist"))[0] == key
    await cache.delete(key)
    assert (await cache.get(key)) is None
    assert len(await (cache.keys())) == 0


@pytest.mark.asyncio
async def test_local_vm_cache():
    cache = TestVmCache()
    await test_cache(cache)
