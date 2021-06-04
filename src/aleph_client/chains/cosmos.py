import json
import ecdsa
import hashlib
import base64

from substrateinterface import Keypair
from .common import (
    BaseAccount,
    get_fallback_private_key,
    get_verification_buffer,
    get_public_key,
    PRIVATE_KEY_FILE,
)

from cosmospy._wallet import privkey_to_address, privkey_to_pubkey
from cosmospy.typing import SyncMode

DEFAULT_HRP = "cosmos"


def get_signable_message(message):
    signable = get_verification_buffer(message).decode("utf-8")
    content_message = {
        "type": "signutil/MsgSignText",
        "value": {
            "message": signable,
            "signer": message["sender"],
        },
    }

    return {
        "chain_id": "signed-message-v1",
        "account_number": str(0),
        "fee": {
            "amount": [],
            "gas": str(0),
        },
        "memo": "",
        "sequence": str(0),
        "msgs": [
            content_message,
        ],
    }


def get_verification_string(message):
    value = get_signable_message(message)
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


class CSDKAccount(BaseAccount):
    CHAIN = "CSDK"
    CURVE = "secp256k1"

    def __init__(self, private_key=None, hrp=DEFAULT_HRP):
        self.private_key = private_key
        self.hrp = hrp

    async def sign_message(self, message):
        message = self._setup_sender(message)

        verif = get_verification_string(message)

        privkey = ecdsa.SigningKey.from_string(self.private_key, curve=ecdsa.SECP256k1)
        signature_compact = privkey.sign_deterministic(
            verif.encode("utf-8"),
            hashfunc=hashlib.sha256,
            sigencode=ecdsa.util.sigencode_string_canonize,
        )
        signature_base64_str = base64.b64encode(signature_compact).decode("utf-8")
        base64_pubkey = base64.b64encode(self.get_public_key()).decode("utf-8")

        sig = {
            "signature": signature_base64_str,
            "pub_key": {"type": "tendermint/PubKeySecp256k1", "value": base64_pubkey},
            "account_number": str(0),
            "sequence": str(0),
        }
        message["signature"] = json.dumps(sig)
        return message

    def get_address(self):
        return privkey_to_address(self.private_key)

    def get_public_key(self):
        return privkey_to_pubkey(self.private_key)


def get_fallback_account(hrp=DEFAULT_HRP):
    return CSDKAccount(private_key=get_fallback_private_key(), hrp=hrp)
