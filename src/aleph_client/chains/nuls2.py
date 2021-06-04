import base64
from nuls2.model.data import (
    read_by_length,
    write_with_length,
    public_key_to_hash,
    address_from_hash,
    sign_recoverable_message,
    NETWORKS,
    recover_message_address,
)
from .common import (
    get_public_key,
    generate_key,
    get_verification_buffer,
    BaseAccount,
    get_fallback_private_key,
)


def get_address(public_key=None, private_key=None, chain_id=1, prefix="NULS"):
    if public_key is None:
        public_key = get_public_key(private_key=private_key)

    return address_from_hash(
        public_key_to_hash(public_key, chain_id=chain_id), prefix=prefix
    )


class NULSAccount(BaseAccount):
    CHAIN = "NULS2"
    CURVE = "secp256k1"

    def __init__(self, private_key=None, chain_id=1, prefix=None):
        self.private_key = private_key
        self.chain_id = chain_id
        if prefix is None:
            self.prefix = NETWORKS[chain_id]
        else:
            self.prefix = prefix

    async def sign_message(self, message):
        # sig = NulsSignature.sign_message(self.private_key,
        #                                  get_verification_buffer(message))
        message = self._setup_sender(message)

        sig = sign_recoverable_message(
            self.private_key, get_verification_buffer(message)
        )
        message["signature"] = base64.b64encode(sig).decode()
        return message

    def get_address(self):
        return address_from_hash(
            public_key_to_hash(self.get_public_key(), chain_id=self.chain_id),
            prefix=self.prefix,
        )

    def get_public_key(self):
        return get_public_key(private_key=self.private_key)


def get_fallback_account(chain_id=1):
    acc = NULSAccount(private_key=get_fallback_private_key(), chain_id=chain_id)
    return acc
