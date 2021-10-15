from unittest.mock import patch

import pytest

from aleph_client.chains.ethereum import ETHAccount
from aleph_client.chains.remote import RemoteAccount, AccountProperties


@pytest.mark.asyncio
async def test_remote_storage():
    host = "http://localhost:8888"
    private_key = (
        b"xRR\xd4P\xdb9\x93(U\xa7\xd5\x81\xba\xc7\x9fiT"
        b"\xb8]\x12\x82 \xd1\x81\xc8\x94\xf0\xdav\xbb\xfb"
    )
    local_account = ETHAccount(private_key=private_key)

    with patch("aiohttp.client.ClientSession") as mock_session:
        mock_session.get.return_value.__aenter__.return_value.json.return_value = (
            AccountProperties(
                chain="ETH",
                curve="secp256k1",
                address=local_account.get_address(),
                public_key=local_account.get_public_key(),
            ).dict()
        )

        remote_account = await RemoteAccount.from_crypto_host(
            host=host, session=mock_session
        )

        assert remote_account.get_address() == local_account.get_address()
        assert remote_account.get_public_key() == local_account.get_public_key()

        # --- Test remote signing ---

        expected_signature = (
            "0xa943de6c550ddf9cd1d3e58e77e9952b9f97e1bcb2c69"
            "a2f4ee56446dc8a38f02fb4a4e85c2d02efa26750456090"
            "3b983b4eef8b8030cc0d89550c18c69aef081c"
        )
        message = {
            "chain": "ETH",
            "sender": local_account.get_address(),
            "type": "POST",
            "item_hash": "HASH",
        }
        expected_signed_message = {
            "signature": expected_signature,
        }
        expected_signed_message.update(message)
        mock_session.post.return_value.__aenter__.return_value.json.return_value = (
            expected_signed_message
        )

        signed_message = await remote_account.sign_message(message)

        assert set(signed_message.keys()) == set(message.keys()).union(["signature"])
        assert signed_message["signature"] == expected_signature

        local_signed_message = await local_account.sign_message(message)
        assert signed_message == local_signed_message
