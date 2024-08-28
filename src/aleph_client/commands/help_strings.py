IPFS_HASH = "IPFS Content identifier (CID)"
CHANNEL = "Aleph.im network channel where the message is or will be broadcasted"
PRIVATE_KEY = "Your private key. Cannot be used with --private-key-file"
PRIVATE_KEY_FILE = "Path to your private key file"
REF = "Checkout https://aleph-im.gitbook.io/aleph-js/api-resources-reference/posts"
SIGNABLE_MESSAGE = "Message to sign"
CUSTOM_DOMAIN_TARGET_TYPES = "IPFS|PROGRAM|INSTANCE"
CUSTOM_DOMAIN_OWNER_ADDRESS = "Owner address, default current account"
CUSTOM_DOMAIN_NAME = "Domain name. ex: aleph.im"
CUSTOM_DOMAIN_ITEM_HASH = "Item hash"
SKIP_VOLUME = "Skip prompt to attach more volumes"
PERSISTENT_VOLUME = """Persistent volumes are allocated on the host machine and are not deleted when the VM is stopped.\n
Requires at least a "mount" and "size_mib". For more info, see the docs: https://docs.aleph.im/computing/volumes/persistent/\n
Example: --persistent_volume persistence=host,size_mib=100,mount=/opt/data"""
EPHEMERAL_VOLUME = """Ephemeral volumes are allocated on the host machine when the VM is started and deleted when the VM is stopped.\n
Example: --ephemeral-volume size_mib=100,mount=/tmp/data"""
IMMUTABLE_VOLUME = """Immutable volumes are pinned on the network and can be used by multiple VMs at the same time. They are read-only and useful for setting up libraries or other dependencies.\n
Requires at least a "ref" (message hash) and "mount" path. "use_latest" is True by default, to use the latest version of the volume, if it has been amended. See the docs for more info: https://docs.aleph.im/computing/volumes/immutable/\n
Example: --immutable-volume ref=25a393222692c2f73489dc6710ae87605a96742ceef7b91de4d7ec34bb688d94,mount=/lib/python3.8/site-packages"""
ASK_FOR_CONFIRMATION = "Prompt user for confirmation"
IPFS_CATCH_ALL_PATH = "Choose a relative path to catch all unmatched route or a 404 error"
PAYMENT_TYPE = "Payment method, either holding tokens or Pay-As-You-Go via token streaming"
HYPERVISOR = "Hypervisor to use to launch your instance. Defaults to QEMU"
INSTANCE_NAME = "Name of your new instance"
ROOTFS = (
    "Hash of the rootfs to use for your instance. Defaults to Ubuntu 22. You can also create your own rootfs and pin it"
)
ROOTFS_SIZE = (
    "Size of the rootfs to use for your instance. If not set, content.size of the --rootfs store message will be used"
)
VCPUS = "Number of virtual CPUs to allocate"
MEMORY = "Maximum memory (RAM) allocation on VM in MiB"
TIMEOUT_SECONDS = "If vm is not called after [timeout_seconds] it will shutdown"
SSH_PUBKEY_FILE = "Path to a public ssh key to be added to the instance"
CRN_HASH = "Hash of the CRN to deploy to"
CRN_URL = "URL of the CRN to deploy to"
CONFIDENTIAL_OPTION = "Launch a confidential instance (requires creating an encrypted volume)"
CONFIDENTIAL_FIRMWARE = "Hash to UEFI Firmware to launch confidential instance"
CONFIDENTIAL_FIRMWARE_HASH = "Hash of the UEFI Firmware content, to validate measure (ignored if path is provided)"
CONFIDENTIAL_FIRMWARE_PATH = "Path to the UEFI Firmware content, to validate measure (instead of the hash)"
KEEP_SESSION = "Keeping the already initiated session"
VM_SECRET = "Secret password to start the VM"
CRN_URL_VM_DELETION = "Domain of the CRN where an associated VM is running. It ensures your VM will be stopped and erased on the CRN before the instance message is actually deleted"
VM_ID = "Item hash of your VM. If provided, skip the instance creation, else create a new one"
VM_NOT_READY = "VM not initialized/started"
VM_SCHEDULED = "VM scheduled but not available yet"
VM_NOT_AVAILABLE_YET = "VM not available yet"
CRN_PENDING = "Pending..."
ALLOCATION_AUTO = "Auto - Scheduler"
ALLOCATION_MANUAL = "Manual - Selection"
PAYMENT_CHAIN = "Chain you want to use to pay for your instance"
