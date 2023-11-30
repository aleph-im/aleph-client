IPFS_HASH = "IPFS Content identifier (CID)"
CHANNEL = "Aleph.im network channel where the message is located"
PRIVATE_KEY = "Your private key. Cannot be used with --private-key-file"
PRIVATE_KEY_FILE = "Path to your private key file"
REF = "Checkout https://aleph-im.gitbook.io/aleph-js/api-resources-reference/posts"
SIGNABLE_MESSAGE = "Message to sign"
CUSTOM_DOMAIN_TARGET_TYPES = "IPFS|PROGRAM|INSTANCE"
CUSTOM_DOMAIN_OWNER_ADDRESS = "Owner address, default current account"
CUSTOM_DOMAIN_NAME = "Domain name. ex: aleph.im"
CUSTOM_DOMAIN_ITEM_HASH = "Item hash"
PERSISTENT_VOLUME = """Persistent volumes are allocated on the host machine and are not deleted when the VM is stopped.\n
Requires at least a "mount" and "size_mib". For more info, see the docs: https://docs.aleph.im/computing/volumes/persistent/\n
Example: --persistent_volume persistence=host,size_mib=100,mount=/opt/data"""
EPHEMERAL_VOLUME = """Ephemeral volumes are allocated on the host machine when the VM is started and deleted when the VM is stopped.\n
Example: --ephemeral-volume size_mib=100,mount=/tmp/data"""
IMMUATABLE_VOLUME = """Immutable volumes are pinned on the network and can be used by multiple VMs at the same time. They are read-only and useful for setting up libraries or other dependencies.\n
Requires at least a "ref" (message hash) and "mount" path. "use_latest" is True by default, to use the latest version of the volume, if it has been amended. See the docs for more info: https://docs.aleph.im/computing/volumes/immutable/\n
Example: --immutable-volume ref=25a393222692c2f73489dc6710ae87605a96742ceef7b91de4d7ec34bb688d94,mount=/lib/python3.8/site-packages"""
