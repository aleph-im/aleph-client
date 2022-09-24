import json
from base64 import b64encode
from substrateinterface import Keypair

from .common import (
    BaseAccount,
    get_verification_buffer,
)
from ..conf import settings


class DOTAccount(BaseAccount):
    CHAIN = "DOT"
    CURVE = "sr25519"

    def __init__(self, mnemonics=None):
        self.mnemonics = mnemonics
        self._account = Keypair.create_from_mnemonic(
            self.mnemonics)

    async def sign_message(self, message):
        message = self._setup_sender(message)
        verif = get_verification_buffer(message).decode("utf-8")
        m = b64encode(b'self._account.sign(verif)').decode('utf-8')
        sig = {"curve": self.CURVE, "data": m}
        message["signature"] = json.dumps(sig)
        return message

    def get_address(self):
        return self._account.ss58_address

    def get_public_key(self):
        return self._account.public_key


def get_fallback_account():
    return DOTAccount(mnemonics=get_fallback_mnemonics())


def get_fallback_mnemonics():
    try:
        with open(settings.PRIVATE_KEY_FILE, "r") as prvfile:
            mnemonic = prvfile.read()
    except OSError:
        mnemonic = Keypair.generate_mnemonic()
        with open(settings.PRIVATE_KEY_FILE, "w") as prvfile:
            prvfile.write(mnemonic)

    return mnemonic
