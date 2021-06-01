from unittest.mock import patch

import pytest

from aleph_client.chains.ethereum import ETHAccount
from aleph_client.chains.remote import RemoteAccount, AccountProperties


@pytest.mark.asyncio
async def test_remote_storage():
    host = "http://localhost:8888"

    with patch('aiohttp.client.ClientSession') as mock_session:

        mock_session.get.return_value.__aenter__.return_value.json.return_value = AccountProperties(
            chain="ETH",
            curve="secp256k1",
            address="ADDR",
            public_key="PUBKEY",
        ).dict()

        remote_account = await RemoteAccount.from_crypto_host(host=host, session=mock_session)

        assert remote_account.get_address() == "ADDR"
        assert remote_account.get_public_key() == "PUBKEY"

        # --- Test remote signing ---

        message = {
            "chain": "ETH",
            "sender": "BOB",
            "type": "POST",
            "item_hash": "HASH",
        }
        private_key = b'xRR\xd4P\xdb9\x93(U\xa7\xd5\x81\xba\xc7\x9fiT' \
                      b'\xb8]\x12\x82 \xd1\x81\xc8\x94\xf0\xdav\xbb\xfb'
        signature = '0x2e578bdeb561d2b0295494dc0d1641df67d7aa5ac5b408ee4b2' \
                    '9124ca4db1da8702a8480af96482462fcfc5721657c9d915aa5a8' \
                    '92189503760018519352e3161b'

        expected_signed_message = {
            'signature': signature,
        }
        expected_signed_message.update(message)
        mock_session.post.return_value.__aenter__.return_value.json.return_value\
            = expected_signed_message

        signed_message = await remote_account.sign_message(message)

        assert set(signed_message.keys()) == set(message.keys()).union(['signature'])
        assert signed_message['signature'] == signature

        local_account = ETHAccount(private_key=private_key)
        local_signed_message = await local_account.sign_message(message)
        assert signed_message == local_signed_message
