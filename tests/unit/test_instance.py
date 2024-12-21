from __future__ import annotations

import random
from datetime import datetime, timezone
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import InvalidURL
from aleph.sdk.chains.evm import EVMAccount
from aleph.sdk.conf import settings
from aleph_message.models import Chain, ItemHash
from aleph_message.models.execution.base import Payment, PaymentType
from aleph_message.models.execution.environment import (
    CpuProperties,
    GpuDeviceClass,
    HypervisorType,
    MachineResources,
)
from eth_utils.currency import to_wei
from multidict import CIMultiDict, CIMultiDictProxy
from pydantic import BaseModel

from aleph_client.commands import help_strings
from aleph_client.commands.instance import (
    allocate,
    create,
    delete,
    list_instances,
    logs,
    reboot,
    stop,
)
from aleph_client.commands.instance.network import fetch_crn_info
from aleph_client.models import (
    CoreFrequencies,
    CpuUsage,
    CRNInfo,
    DiskUsage,
    GpuDevice,
    GPUProperties,
    LoadAverage,
    MachineInfo,
    MachineProperties,
    MachineUsage,
    MemoryUsage,
    UsagePeriod,
)
from aleph_client.utils import FORBIDDEN_HOSTS, sanitize_url

# Utils
settings.API_HOST = "https://api.twentysix.testnet.network"
FAKE_PUBKEY_FILE = "/path/fake/pubkey"
FAKE_PRIVATE_KEY = b"cafe" * 8
FAKE_ADDRESS_EVM = "0x00001A0e6B9a46Be48a294D74D897d9C48678862"
FAKE_STORE_HASH = "102682ea8bcc0cec9c42f32fbd2660286b4eb31003108440988343726304607a"  # Needs to exist on Aleph Testnet
FAKE_VM_HASH = "ab12" * 16
FAKE_CRN_HASH = "cd34" * 16
FAKE_CRN_URL = "https://ovh.staging.aleph.sh"


def dummy_gpu_device() -> GpuDevice:
    return GpuDevice(
        vendor="NVIDIA",
        device_name="RTX 4090",
        device_class=GpuDeviceClass.VGA_COMPATIBLE_CONTROLLER,
        pci_host="01:00.0",
        device_id="abcd:1234",
    )


def dummy_machine_info() -> MachineInfo:
    """Create a dummy MachineInfo object for testing purposes."""

    gpu_devices = [dummy_gpu_device()]
    return MachineInfo(
        hash=FAKE_CRN_HASH,
        name="Mock CRN",
        url="https://example.com",
        version="v420.69",
        score=0.5,
        reward_address=FAKE_ADDRESS_EVM,
        machine_usage=MachineUsage(
            cpu=CpuUsage(
                count=8,
                load_average=LoadAverage(load1=0.5, load5=0.4, load15=0.3),
                core_frequencies=CoreFrequencies(min=1.0, max=2.0),
            ),
            mem=MemoryUsage(
                total_kB=32_000_000,
                available_kB=28_000_000,
            ),
            disk=DiskUsage(
                total_kB=1_000_000_000,
                available_kB=500_000_000,
            ),
            period=UsagePeriod(
                start_timestamp=datetime.now(tz=timezone.utc),
                duration_seconds=60,
            ),
            properties=MachineProperties(
                cpu=CpuProperties(
                    architecture="x86_64",
                    vendor="AuthenticAMD",
                ),
            ),
            gpu=GPUProperties(
                devices=gpu_devices,
                available_devices=gpu_devices,
            ),
        ),
    )


def create_mock_crn_info():
    mock_machine_info = dummy_machine_info()
    return MagicMock(
        return_value=CRNInfo(
            hash=ItemHash(FAKE_CRN_HASH),
            name="Mock CRN",
            url=FAKE_CRN_URL,
            version="v420.69",
            score=0.5,
            stream_reward_address=mock_machine_info.reward_address,
            machine_usage=mock_machine_info.machine_usage,
            qemu_support=True,
            confidential_computing=True,
            gpu_support=True,
        )
    )


def dict_to_ci_multi_dict_proxy(d: dict) -> CIMultiDictProxy:
    """Return a read-only proxy to a case-insensitive multi-dict created from a dict."""
    return CIMultiDictProxy(CIMultiDict(d))


@pytest.mark.asyncio
async def test_fetch_crn_info() -> None:
    # Test with valid node
    # TODO: Mock the response from the node, don't rely on a real node
    node_url = "https://ovh.staging.aleph.sh"
    info = await fetch_crn_info(node_url)
    assert info
    assert info["machine_usage"]

    # Test with invalid node
    invalid_node_url = "https://coconut.example.org/"
    assert not (await fetch_crn_info(invalid_node_url))

    # TODO: Test different error handling


def test_sanitize_url_with_empty_url():
    with pytest.raises(InvalidURL, match="Empty URL"):
        sanitize_url("")


def test_sanitize_url_with_invalid_scheme():
    with pytest.raises(InvalidURL, match="Invalid URL scheme"):
        sanitize_url("ftp://example.org")


def test_sanitize_url_with_forbidden_host():
    for host in FORBIDDEN_HOSTS:
        with pytest.raises(InvalidURL, match="Invalid URL host"):
            sanitize_url(f"http://{host}")


def test_sanitize_url_with_valid_url():
    url = "http://example.org"
    assert sanitize_url(url) == url


def test_sanitize_url_with_https_scheme():
    url = "https://example.org"
    assert sanitize_url(url) == url


class MockEVMAccount(EVMAccount):
    pass


def create_test_account() -> MockEVMAccount:
    return MockEVMAccount(private_key=FAKE_PRIVATE_KEY)


def create_mock_load_account():
    mock_account = create_test_account()
    mock_loader = MagicMock(return_value=mock_account)
    mock_loader.return_value.get_super_token_balance = MagicMock(return_value=Decimal(10000 * (10**18)))
    mock_loader.return_value.can_transact = MagicMock(return_value=True)
    mock_loader.return_value.superfluid_connector = MagicMock(can_start_flow=MagicMock(return_value=True))
    return mock_loader


class Dict(BaseModel):
    class Config:
        extra = "allow"


def create_mock_instance_message(mock_account, payg=False, coco=False, gpu=False):
    tmp = list(FAKE_VM_HASH)
    random.shuffle(tmp)
    vm_item_hash = "".join(tmp)
    vm = Dict(
        chain=Chain.ETH,
        sender=mock_account.get_address(),
        type="instance",
        channel="ALEPH-CLOUDSOLUTIONS",
        confirmed=True,
        item_type="inline",
        item_hash=vm_item_hash,
        content=Dict(
            address=mock_account.get_address(),
            time=1734037086.2333803,
            metadata=dict(name="mock_instance"),
            authorized_keys=["ssh-rsa ..."],
            environment=Dict(hypervisor=HypervisorType.qemu, trusted_execution=None),
            resources=Dict(vcpus=1, memory=2048),
            payment=Payment(chain=Chain.ETH, receiver=None, type=PaymentType.hold),
            requirements=None,
            rootfs=Dict(
                parent=Dict(ref=FAKE_STORE_HASH),
                size_mib=20480,
            ),
            volumes=[],
        ),
    )
    if payg or coco or gpu:
        vm.content.metadata["name"] += "_payg"  # type: ignore
        vm.content.payment = Payment(chain=Chain.AVAX, receiver=FAKE_ADDRESS_EVM, type=PaymentType.superfluid)  # type: ignore
        vm.content.requirements = Dict(  # type: ignore
            node=Dict(
                node_hash=FAKE_CRN_HASH,
                terms_and_conditions=None,
            ),
            gpu=None,
        )
    if coco:
        vm.content.metadata["name"] += "_coco"  # type: ignore
        vm.content.environment.trusted_execution = Dict(firmware=FAKE_STORE_HASH)  # type: ignore
    if gpu:
        vm.content.metadata["name"] += "_gpu"  # type: ignore
        vm.content.requirements.gpu = [  # type: ignore
            Dict(
                vendor="NVIDIA",
                device_name="RTX 4090",
                device_class=GpuDeviceClass.VGA_COMPATIBLE_CONTROLLER,
                device_id="abcd:1234",
            )
        ]
    return vm


def create_mock_instance_messages(mock_account):
    regular = create_mock_instance_message(mock_account)
    payg = create_mock_instance_message(mock_account, payg=True)
    coco = create_mock_instance_message(mock_account, coco=True)
    gpu = create_mock_instance_message(mock_account, gpu=True)
    return AsyncMock(return_value=[regular, payg, coco, gpu])


def create_mock_validate_ssh_pubkey_file():
    return MagicMock(
        return_value=MagicMock(return_value=FAKE_PUBKEY_FILE, read_text=MagicMock(return_value="ssh-rsa ..."))
    )


def mock_fetch_vm_info():
    return AsyncMock(
        return_value=[FAKE_VM_HASH, dict(crn_url=FAKE_CRN_URL, allocation_type=help_strings.ALLOCATION_MANUAL)]
    )


def create_mock_client():
    mock_client = AsyncMock(get_message=AsyncMock(return_value=True))
    mock_client_class = MagicMock()
    mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)
    return mock_client_class, mock_client


def create_mock_auth_client(mock_account):
    mock_response_get_message = create_mock_instance_message(mock_account, payg=True)
    mock_response_create_instance = MagicMock(item_hash=FAKE_VM_HASH)
    mock_auth_client = AsyncMock(
        get_message=AsyncMock(return_value=mock_response_get_message),
        create_instance=AsyncMock(return_value=[mock_response_create_instance, MagicMock()]),
        get_program_price=AsyncMock(return_value=MagicMock(required_tokens=0.0001)),
        forget=AsyncMock(return_value=(MagicMock(), MagicMock())),
    )
    mock_auth_client_class = MagicMock()
    mock_auth_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_auth_client)
    return mock_auth_client_class, mock_auth_client


def create_mock_vm_client():
    class MockAsyncIteratorLogs:
        def __init__(self, *args, **kwargs):
            self.items = ['{"message": "Log message 1"}', '{"message": "Log message 2"}']

        def __aiter__(self):
            return self

        async def __anext__(self):
            if not self.items:
                raise StopAsyncIteration
            return self.items.pop(0)

    mock_vm_client = AsyncMock(
        start_instance=AsyncMock(return_value=[200, MagicMock()]),
        erase_instance=AsyncMock(return_value=[200, MagicMock()]),
        reboot_instance=AsyncMock(return_value=[200, MagicMock()]),
        stop_instance=AsyncMock(return_value=[200, MagicMock()]),
        get_logs=MagicMock(return_value=MockAsyncIteratorLogs()),
    )
    mock_vm_client_class = MagicMock()
    mock_vm_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_vm_client)
    return mock_vm_client_class, mock_vm_client


@pytest.mark.parametrize(
    ids=[
        "regular_hold_evm",
        "regular_superfluid_evm",
        "regular_hold_sol",
        "coco_hold_sol",
        "coco_hold_evm",
        "coco_superfluid_evm",
        "gpu_superfluid_evm",
    ],
    argnames="args, expected",
    argvalues=[
        (  # regular_hold_evm
            dict(
                payment_type="hold",
                payment_chain="ETH",
                rootfs="debian12",
            ),
            (FAKE_VM_HASH, None, "ETH"),
        ),
        (  # regular_superfluid_evm
            dict(
                payment_type="superfluid",
                payment_chain="AVAX",
                rootfs="debian12",
                crn_hash=FAKE_CRN_HASH,
                crn_url=FAKE_CRN_URL,
            ),
            (FAKE_VM_HASH, FAKE_CRN_URL, "AVAX"),
        ),
        (  # regular_hold_sol
            dict(
                payment_type="hold",
                payment_chain="SOL",
                rootfs="debian12",
            ),
            (FAKE_VM_HASH, None, "SOL"),
        ),
        (  # coco_hold_sol
            dict(
                payment_type="hold",
                payment_chain="SOL",
                rootfs=FAKE_STORE_HASH,
                crn_hash=FAKE_CRN_HASH,
                crn_url=FAKE_CRN_URL,
                confidential=True,
                confidential_firmware=FAKE_STORE_HASH,
            ),
            (FAKE_VM_HASH, FAKE_CRN_URL, "SOL"),
        ),
        (  # coco_hold_evm
            dict(
                payment_type="hold",
                payment_chain="ETH",
                rootfs=FAKE_STORE_HASH,
                crn_hash=FAKE_CRN_HASH,
                crn_url=FAKE_CRN_URL,
                confidential=True,
                confidential_firmware=FAKE_STORE_HASH,
            ),
            (FAKE_VM_HASH, FAKE_CRN_URL, "ETH"),
        ),
        (  # coco_superfluid_evm
            dict(
                payment_type="superfluid",
                payment_chain="BASE",
                rootfs=FAKE_STORE_HASH,
                crn_hash=FAKE_CRN_HASH,
                crn_url=FAKE_CRN_URL,
                confidential=True,
                confidential_firmware=FAKE_STORE_HASH,
            ),
            (FAKE_VM_HASH, FAKE_CRN_URL, "BASE"),
        ),
        (  # gpu_superfluid_evm
            dict(
                payment_type="superfluid",
                payment_chain="BASE",
                rootfs="debian12",
                crn_hash=FAKE_CRN_HASH,
                crn_url=FAKE_CRN_URL,
                gpu=True,
            ),
            (FAKE_VM_HASH, FAKE_CRN_URL, "BASE"),
        ),
    ],
)
@pytest.mark.asyncio
async def test_create_instance(args, expected):
    mock_validate_ssh_pubkey_file = create_mock_validate_ssh_pubkey_file()
    mock_load_account = create_mock_load_account()
    mock_account = mock_load_account.return_value
    mock_client_class, _ = create_mock_client()
    mock_auth_client_class, mock_auth_client = create_mock_auth_client(mock_account)
    mock_vm_client_class, mock_vm_client = create_mock_vm_client()
    mock_crn_info = create_mock_crn_info()
    mock_validated_int_prompt = MagicMock(return_value=1)
    mock_wait_for_processed_instance = AsyncMock()
    mock_update_flow = AsyncMock(return_value="fake_flow_hash")
    mock_wait_for_confirmed_flow = AsyncMock()

    @patch("aleph_client.commands.instance.validate_ssh_pubkey_file", mock_validate_ssh_pubkey_file)
    @patch("aleph_client.commands.instance._load_account", mock_load_account)
    @patch("aleph_client.commands.instance.AlephHttpClient", mock_client_class)
    @patch("aleph_client.commands.instance.AuthenticatedAlephHttpClient", mock_auth_client_class)
    @patch("aleph_client.commands.instance.CRNInfo", mock_crn_info)
    @patch("aleph_client.commands.instance.validated_int_prompt", mock_validated_int_prompt)
    @patch("aleph_client.commands.instance.wait_for_processed_instance", mock_wait_for_processed_instance)
    @patch("aleph_client.commands.instance.update_flow", mock_update_flow)
    @patch("aleph_client.commands.instance.wait_for_confirmed_flow", mock_wait_for_confirmed_flow)
    @patch("aleph_client.commands.instance.VmClient", mock_vm_client_class)
    async def create_instance(instance_spec):
        print()  # For better display when pytest -v -s
        all_args = dict(
            ssh_pubkey_file=FAKE_PUBKEY_FILE,
            name="mock_instance",
            hypervisor=HypervisorType.qemu,
            rootfs_size=20480,
            vcpus=1,
            memory=2048,
            skip_volume=True,
            crn_hash=None,
            crn_url=None,
            confidential=False,
            gpu=False,
            print_message=False,
            debug=False,
        )
        all_args.update(instance_spec)
        return await create(**all_args)

    returned = await create_instance(args)
    mock_load_account.assert_called_once()
    mock_validate_ssh_pubkey_file.return_value.read_text.assert_called_once()
    mock_auth_client.create_instance.assert_called_once()
    if args["payment_type"] == "superfluid":
        mock_wait_for_processed_instance.assert_called_once()
        mock_update_flow.assert_called_once()
        mock_wait_for_confirmed_flow.assert_called_once()
        mock_vm_client.start_instance.assert_called_once()
    assert returned == expected


@pytest.mark.asyncio
async def test_list_instances():
    mock_load_account = create_mock_load_account()
    mock_account = mock_load_account.return_value
    mock_auth_client_class, mock_auth_client = create_mock_auth_client(mock_account)
    mock_instance_messages = create_mock_instance_messages(mock_account)

    @patch("aleph_client.commands.instance._load_account", mock_load_account)
    @patch("aleph_client.commands.instance.AlephHttpClient", mock_auth_client_class)
    @patch("aleph_client.commands.instance.filter_only_valid_messages", mock_instance_messages)
    async def list_instance():
        print()  # For better display when pytest -v -s
        await list_instances(
            address=mock_account.get_address(),
            chain=Chain.ETH,
            json=False,
            debug=False,
        )
        mock_instance_messages.assert_called_once()
        mock_auth_client.get_messages.assert_called_once()
        mock_auth_client.get_program_price.assert_called()
        assert mock_auth_client.get_program_price.call_count == 3

    await list_instance()


@pytest.mark.asyncio
async def test_delete_instance():
    mock_load_account = create_mock_load_account()
    mock_account = mock_load_account.return_value
    mock_auth_client_class, mock_auth_client = create_mock_auth_client(mock_account)
    mock_vm_client_class, mock_vm_client = create_mock_vm_client()
    mock_get_flow = AsyncMock(return_value={"flowRate": to_wei(0.0001, unit="ether")})
    mock_delete_flow = AsyncMock()

    @patch("aleph_client.commands.instance._load_account", mock_load_account)
    @patch("aleph_client.commands.instance.AuthenticatedAlephHttpClient", mock_auth_client_class)
    @patch("aleph_client.commands.instance.fetch_vm_info", mock_fetch_vm_info())
    @patch("aleph_client.commands.instance.VmClient", mock_vm_client_class)
    @patch.object(mock_account, "get_flow", mock_get_flow)
    @patch.object(mock_account, "delete_flow", mock_delete_flow)
    async def delete_instance():
        print()  # For better display when pytest -v -s
        await delete(
            FAKE_VM_HASH,
            domain=None,
            print_message=False,
            debug=False,
        )
        mock_auth_client.get_message.assert_called_once()
        mock_vm_client.erase_instance.assert_called_once()
        mock_delete_flow.assert_awaited_once()
        mock_auth_client.forget.assert_called_once()

    await delete_instance()


@pytest.mark.asyncio
async def test_reboot_instance():
    mock_load_account = create_mock_load_account()
    mock_account = mock_load_account.return_value
    mock_auth_client_class, mock_auth_client = create_mock_auth_client(mock_account)
    mock_vm_client_class, mock_vm_client = create_mock_vm_client()

    @patch("aleph_client.commands.instance._load_account", mock_load_account)
    @patch("aleph_client.commands.instance.network.AlephHttpClient", mock_auth_client_class)
    @patch("aleph_client.commands.instance.network.fetch_vm_info", mock_fetch_vm_info())
    @patch("aleph_client.commands.instance.VmClient", mock_vm_client_class)
    async def reboot_instance():
        print()  # For better display when pytest -v -s
        await reboot(
            FAKE_VM_HASH,
            domain=None,
            chain=Chain.AVAX,
            debug=False,
        )
        mock_auth_client.get_message.assert_called_once()
        mock_vm_client.reboot_instance.assert_called_once()

    await reboot_instance()


@pytest.mark.asyncio
async def test_allocate_instance():
    mock_load_account = create_mock_load_account()
    mock_account = mock_load_account.return_value
    mock_auth_client_class, mock_auth_client = create_mock_auth_client(mock_account)
    mock_vm_client_class, mock_vm_client = create_mock_vm_client()

    @patch("aleph_client.commands.instance._load_account", mock_load_account)
    @patch("aleph_client.commands.instance.network.AlephHttpClient", mock_auth_client_class)
    @patch("aleph_client.commands.instance.network.fetch_vm_info", mock_fetch_vm_info())
    @patch("aleph_client.commands.instance.VmClient", mock_vm_client_class)
    async def allocate_instance():
        print()  # For better display when pytest -v -s
        await allocate(
            FAKE_VM_HASH,
            domain=None,
            chain=Chain.AVAX,
            debug=False,
        )
        mock_auth_client.get_message.assert_called_once()
        mock_vm_client.start_instance.assert_called_once()

    await allocate_instance()


@pytest.mark.asyncio
async def test_logs_instance():
    mock_load_account = create_mock_load_account()
    mock_account = mock_load_account.return_value
    mock_auth_client_class, mock_auth_client = create_mock_auth_client(mock_account)
    mock_vm_client_class, mock_vm_client = create_mock_vm_client()

    @patch("aleph_client.commands.instance._load_account", mock_load_account)
    @patch("aleph_client.commands.instance.network.AlephHttpClient", mock_auth_client_class)
    @patch("aleph_client.commands.instance.network.fetch_vm_info", mock_fetch_vm_info())
    @patch("aleph_client.commands.instance.VmClient", mock_vm_client_class)
    async def logs_instance():
        print()  # For better display when pytest -v -s
        await logs(
            FAKE_VM_HASH,
            domain=None,
            chain=Chain.AVAX,
            debug=False,
        )
        mock_auth_client.get_message.assert_called_once()
        mock_vm_client.get_logs.assert_called_once()

    await logs_instance()


@pytest.mark.asyncio
async def test_stop_instance():
    mock_load_account = create_mock_load_account()
    mock_account = mock_load_account.return_value
    mock_auth_client_class, mock_auth_client = create_mock_auth_client(mock_account)
    mock_vm_client_class, mock_vm_client = create_mock_vm_client()

    @patch("aleph_client.commands.instance._load_account", mock_load_account)
    @patch("aleph_client.commands.instance.network.AlephHttpClient", mock_auth_client_class)
    @patch("aleph_client.commands.instance.network.fetch_vm_info", mock_fetch_vm_info())
    @patch("aleph_client.commands.instance.VmClient", mock_vm_client_class)
    async def stop_instance():
        print()  # For better display when pytest -v -s
        await stop(
            FAKE_VM_HASH,
            domain=None,
            chain=Chain.AVAX,
            debug=False,
        )
        mock_auth_client.get_message.assert_called_once()
        mock_vm_client.stop_instance.assert_called_once()

    await stop_instance()
