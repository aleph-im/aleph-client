from .common import (BaseAccount, get_fallback_private_key,
                     get_verification_buffer, get_public_key)

from eth_account.messages import encode_defunct
from eth_account import Account

class ETHAccount(BaseAccount):
    CHAIN = "ETH"
    def __init__(self, private_key=None):
        self.private_key = private_key
        self._account = Account.from_key(self.private_key)
    
    def sign_message(self, message):
        msghash = encode_defunct(text=get_verification_buffer(message).decode('utf-8'))
        sig = self._account.sign_message(msghash)
        message['signature'] = sig['signature'].hex()
        return message
    
    def get_address(self):
        return self._account.address
    
    def get_public_key(self):
        return get_public_key(private_key=self.private_key)
    
def get_fallback_account():
    return ETHAccount(private_key=get_fallback_private_key())