import pytest
from aleph_client.chains.common import get_fallback_private_key
from aleph_client.chains.ethereum import ETHAccount

NODE_UNDER_TEST = "http://163.172.70.92:4024"
REFERENCE_NODE = "https://api2.aleph.im:4024"

@pytest.fixture
def fixture_account():
    private_key = get_fallback_private_key()
    return ETHAccount(private_key)
