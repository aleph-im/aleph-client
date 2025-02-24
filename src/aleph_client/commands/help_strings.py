IPFS_HASH = "IPFS Content identifier (CID)"
CHANNEL = "Aleph.im network channel where the message is or will be broadcasted"
PRIVATE_KEY = "Your private key. Cannot be used with --private-key-file"
PRIVATE_KEY_FILE = "Path to your private key file"
REF = "Item hash of the message to update"
SIGNABLE_MESSAGE = "Message to sign"
CUSTOM_DOMAIN_TARGET_TYPES = "IPFS|PROGRAM|INSTANCE"
CUSTOM_DOMAIN_OWNER_ADDRESS = "Owner address. Defaults to current account address"
CUSTOM_DOMAIN_NAME = "Domain name. ex: aleph.im"
CUSTOM_DOMAIN_ITEM_HASH = "Item hash"
SKIP_VOLUME = "Skip prompt to attach more volumes"
PERSISTENT_VOLUME = "Persistent volumes are allocated on the host machine and are not deleted when the VM is stopped.\nRequires at least `name`, `mount` path, and `size_mib`. To add multiple, reuse the same argument.\nExample: --persistent-volume name=data,mount=/opt/data,size_mib=1000.\nFor more info, see the docs: https://docs.aleph.im/computing/volumes/persistent/"
EPHEMERAL_VOLUME = "Ephemeral volumes are allocated on the host machine when the VM is started and deleted when the VM is stopped.\nRequires at least `mount` path and `size_mib`. To add multiple, reuse the same argument.\nExample: --ephemeral-volume mount=/opt/tmp,size_mib=100"
IMMUTABLE_VOLUME = "Immutable volumes are pinned on the network and can be used by multiple VMs at the same time. They are read-only and useful for setting up libraries or other dependencies.\nRequires at least `mount` path and `ref` (volume message hash). `use_latest` is True by default, to use the latest version of the volume, if it has been amended. To add multiple, reuse the same argument.\nExample: --immutable-volume mount=/opt/packages,ref=25a3...8d94.\nFor more info, see the docs: https://docs.aleph.im/computing/volumes/immutable/"
SKIP_ENV_VAR = "Skip prompt to set environment variables"
ENVIRONMENT_VARIABLES = "Environment variables to pass. They will be public and visible in the message, so don't include secrets. Must be a comma separated list. Example: `KEY=value` or `KEY=value,KEY=value`"
ASK_FOR_CONFIRMATION = "Prompt user for confirmation"
IPFS_CATCH_ALL_PATH = "Choose a relative path to catch all unmatched route or a 404 error"
PAYMENT_TYPE = "Payment method, either holding tokens, NFTs, or Pay-As-You-Go via token streaming"
HYPERVISOR = "Hypervisor to use to launch your instance. Always defaults to QEMU, since Firecracker is now deprecated for instances"
INSTANCE_NAME = "Name of your new instance"
ROOTFS = (
    "Hash of the rootfs to use for your instance. Defaults to Ubuntu 22. You can also create your own rootfs and pin it"
)
COMPUTE_UNITS = "Number of compute units to allocate. Compute units correspond to a tier that includes vcpus, memory, disk and gpu presets. For reference, run: `aleph pricing --help`"
ROOTFS_SIZE = "Rootfs size in MiB to allocate. Set to 0 to use default tier value and to not get prompted"
VCPUS = "Number of virtual CPUs to allocate"
MEMORY = "Maximum memory (RAM) in MiB to allocate"
TIMEOUT_SECONDS = "If vm is not called after [timeout_seconds] it will shutdown"
SSH_PUBKEY_FILE = "Path to a public ssh key to be added to the instance"
CRN_HASH = "Hash of the CRN to deploy to (only applicable for confidential and/or Pay-As-You-Go instances)"
CRN_URL = "URL of the CRN to deploy to (only applicable for confidential and/or Pay-As-You-Go instances)"
CRN_AUTO_TAC = "Automatically accept the Terms & Conditions of the CRN if you read them beforehand"
CONFIDENTIAL_OPTION = "Launch a confidential instance (requires creating an encrypted volume)"
CONFIDENTIAL_FIRMWARE = "Hash to UEFI Firmware to launch confidential instance"
CONFIDENTIAL_FIRMWARE_HASH = "Hash of the UEFI Firmware content, to validate measure (ignored if path is provided)"
CONFIDENTIAL_FIRMWARE_PATH = "Path to the UEFI Firmware content, to validate measure (instead of the hash)"
GPU_OPTION = "Launch an instance attaching a GPU to it"
GPU_PREMIUM_OPTION = "Use Premium GPUs (VRAM > 48GiB)"
KEEP_SESSION = "Keeping the already initiated session"
VM_SECRET = "Secret password to start the VM"
CRN_URL_VM_DELETION = "Domain of the CRN where an associated VM is running. It ensures your VM will be stopped and erased on the CRN before the instance message is actually deleted"
VM_ID = "Item hash of your VM. If provided, skip the instance creation, else create a new one"
VM_NOT_READY = "VM not allocated, initialized, or started"
VM_SCHEDULED = "VM scheduled but not available yet"
CRN_UNKNOWN = "Unknown"
CRN_PENDING = "Pending..."
ALLOCATION_AUTO = "Auto - Scheduler"
ALLOCATION_MANUAL = "Manual - Selection"
PAYMENT_CHAIN = "Chain you want to use to pay for your instance"
PAYMENT_CHAIN_USED = "Chain you are using to pay for your instance"
PAYMENT_CHAIN_PROGRAM = "Chain you want to use to pay for your program"
PAYMENT_CHAIN_PROGRAM_USED = "Chain you are using to pay for your program"
ORIGIN_CHAIN = "Chain of origin of your private key (ensuring correct parsing)"
ADDRESS_CHAIN = "Chain for the address"
ADDRESS_PAYER = "Address of the payer. In order to delegate the payment, your account must be authorized beforehand to publish on the behalf of this address. See the docs for more info: https://docs.aleph.im/protocol/permissions/"
CREATE_REPLACE = "Overwrites private key file if it already exists"
CREATE_ACTIVE = "Loads the new private key after creation"
PROMPT_CRN_URL = "URL of the CRN (Compute node) on which the instance is running"
PROMPT_PROGRAM_CRN_URL = "URL of the CRN (Compute node) on which the program is running"
PROGRAM_PATH = "Path to your source code. Can be a directory, a .squashfs file or a .zip archive"
PROGRAM_ENTRYPOINT = "Your program entrypoint. Example: `main:app` for Python programs, else `run.sh` for a script containing your launch command"
PROGRAM_RUNTIME = "Hash of the runtime to use for your program. You can also create your own runtime and pin it. Currently defaults to `{runtime_id}` (Use `aleph program runtime-checker` to inspect it)"
PROGRAM_INTERNET = "Enable internet access for your program. By default, internet access is disabled"
PROGRAM_PERSISTENT = "Create your program as persistent. By default, programs are ephemeral (serverless): they only start when called and then shutdown after the defined timeout delay."
PROGRAM_UPDATABLE = "Allow program updates. By default, only the source code can be modified without requiring redeployement (same item hash). When enabled (set to True), this option allows to update any other field. However, such modifications will require a program redeployment (new item hash)"
PROGRAM_BETA = "If true, you will be prompted to add message subscriptions to your program"
PROGRAM_KEEP_CODE = "Keep the source code intact instead of deleting it"
PROGRAM_KEEP_PREV = "Keep the previous program intact instead of deleting it"
TARGET_ADDRESS = "Target address. Defaults to current account address"
AGGREGATE_SECURITY_KEY_PROTECTED = (
    "The aggregate key `security` is protected. Use `aleph aggregate [allow|revoke]` to manage it."
)
