from coincurve import PrivateKey, PublicKey
# In case we don't want to bother with handling private key ourselves
# do an ugly and insecure write and read from disk to this file.
PRIVATE_KEY_FILE = 'device.key'

def get_verification_buffer(message):
    """ Returns a serialized string to verify the message integrity
    (this is was it signed)
    """
    return '{chain}\n{sender}\n{type}\n{item_hash}'.format(**message)\
        .encode('utf-8')


def get_public_key(private_key):
    privkey = PrivateKey(private_key)
    return privkey.public_key.format()

class BaseAccount:
    CHAIN = None
    
    def __init__(self):
        raise NotImplementedError
    
    def sign_message(self, message):
        raise NotImplementedError
    
    def get_address(self):
        raise NotImplementedError
    
    def get_public_key(self):
        raise NotImplementedError

# Start of the ugly stuff
def generate_key():
    privkey = PrivateKey()
    return privkey.secret


def get_fallback_private_key():
    try:
        with open(PRIVATE_KEY_FILE, "rb") as prvfile:
            private_key = prvfile.read()
    except OSError:
        private_key = generate_key()
        with open(PRIVATE_KEY_FILE, "wb") as prvfile:
            prvfile.write(private_key)

    return private_key