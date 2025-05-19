from __future__ import annotations

import asyncio
import random
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest
from aiohttp import InvalidURL
from aleph.sdk.exceptions import InsufficientFundsError
from aleph.sdk.types import TokenType
from aleph_message.models import Chain, ItemHash
from aleph_message.models import Chain
from aleph_message.models.execution.base import Payment, PaymentType
from aleph_message.models.execution.environment import (
    CpuProperties,
    GpuDeviceClass,
    HypervisorType,
)
from multidict import CIMultiDict, CIMultiDictProxy
from typer import Exit

from aleph_client.commands.instance import (
    allocate,
    confidential_create,
    confidential_init_session,
    confidential_start,
    create,
    delete,
    gpu_create,
    list_instances,
    logs,
    reboot,
    stop,
)
from aleph_client.commands.instance.network import fetch_crn_info
from aleph_client.models import (
    CoreFrequencies,
    CpuUsage,
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

from .conftest import MOCK_METADATA_ID, MOCK_VOUCHER_ID
from .mocks import (
    FAKE_ADDRESS_EVM,
    FAKE_CRN_BASIC_HASH,
    FAKE_CRN_BASIC_URL,
    FAKE_CRN_CONF_HASH,
    FAKE_CRN_CONF_URL,
    FAKE_CRN_GPU_HASH,
    FAKE_CRN_GPU_URL,
    FAKE_PUBKEY_FILE,
    FAKE_STORE_HASH,
    FAKE_VM_HASH,
    Dict,
    create_mock_load_account,
)


def dummy_gpu_device() -> GpuDevice:
    return GpuDevice(
        vendor="NVIDIA",
        model="RTX 4090",
        device_name="RTX 4090",
        device_class=GpuDeviceClass.VGA_COMPATIBLE_CONTROLLER,
        pci_host="01:00.0",
        device_id="abcd:1234",
        compatible=True,
    )


def dummy_machine_info() -> MachineInfo:
    """Create a dummy MachineInfo object for testing purposes."""

    gpu_devices = [dummy_gpu_device()]
    return MachineInfo(
        hash=FAKE_CRN_BASIC_HASH,
        name="Mock CRN",
        url=FAKE_CRN_BASIC_URL,
        version="123.420.69",
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


def dict_to_ci_multi_dict_proxy(d: dict) -> CIMultiDictProxy:
    """Return a read-only proxy to a case-insensitive multi-dict created from a dict."""
    return CIMultiDictProxy(CIMultiDict(d))


def create_mock_fetch_latest_crn_version():
    return AsyncMock(return_value="0.0.0")


@pytest.mark.asyncio
async def test_fetch_crn_info(mock_crn_list):
    # Test with valid node
    node_url = "https://test.basic.crn.com"
    info = await fetch_crn_info(mock_crn_list, node_url)
    assert info
    assert hasattr(info, "machine_usage")

    node_url = "https://test.gpu.crn.com"
    info = await fetch_crn_info(mock_crn_list, node_url)
    assert info.compatible_available_gpus is not None

    invalid_node_url = "https://coconut.example.org/"
    assert not (await fetch_crn_info(mock_crn_list, invalid_node_url))


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


def create_mock_instance_message(mock_account, payg=False, coco=False, gpu=False, tac=False):
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
            time=2999999999.1234567,
            metadata={"name": "mock_instance"},
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
    if payg or coco or gpu or tac:
        vm.content.metadata["name"] += "_payg"  # type: ignore
        vm.content.payment = Payment(chain=Chain.AVAX, receiver=FAKE_ADDRESS_EVM, type=PaymentType.superfluid)  # type: ignore

        # We load the good CRN for the good Type of VM
        if coco:
            crn_hash = FAKE_CRN_CONF_HASH
        elif payg:
            crn_hash = FAKE_CRN_GPU_HASH
        else:
            crn_hash = FAKE_CRN_BASIC_HASH

        vm.content.requirements = Dict(  # type: ignore
            node=Dict(
                node_hash=crn_hash,
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
    if tac:
        vm.content.metadata["name"] += "_tac"  # type: ignore
        vm.content.requirements.node.terms_and_conditions = FAKE_STORE_HASH  # type: ignore
    return vm


def create_mock_instance_messages(mock_account):
    regular = create_mock_instance_message(mock_account)
    payg = create_mock_instance_message(mock_account, payg=True)
    coco = create_mock_instance_message(mock_account, coco=True)
    gpu = create_mock_instance_message(mock_account, gpu=True)
    tac = create_mock_instance_message(mock_account, tac=True)
    return AsyncMock(return_value=[regular, payg, coco, gpu, tac])


def create_mock_validate_ssh_pubkey_file():
    return MagicMock(
        return_value=MagicMock(return_value=FAKE_PUBKEY_FILE, read_text=MagicMock(return_value="ssh-rsa ..."))
    )


def create_mock_shutil():
    return MagicMock(which=MagicMock(return_value="/root/.cargo/bin/sevctl", move=MagicMock(return_value="/fake/path")))


def create_mock_client(mock_crn_list, payment_type="superfluid", mock_voucher_service=None):
    # Create a proper mock for the crn service
    mock_crn_service = MagicMock()
    mock_crn_service.get_crns_list = AsyncMock(return_value={"crns": mock_crn_list})

    mock_client = AsyncMock(
        get_message=AsyncMock(return_value=True),
        get_stored_content=AsyncMock(
            return_value=Dict(filename="fake_tac", hash="0xfake_tac", url="https://fake.tac.com")
        ),
        get_estimated_price=AsyncMock(
            return_value=MagicMock(
                required_tokens=0.00001527777777777777 if payment_type == "superfluid" else 1000,
                payment_type=payment_type,
            )
        ),
    )
    # Set the service attributes
    mock_client.crn = mock_crn_service
    mock_client.voucher = mock_voucher_service

    mock_client_class = MagicMock()
    mock_client_class.return_value.__aenter__ = AsyncMock(return_value=mock_client)

    return mock_client_class, mock_client


def create_mock_auth_client(mock_account, payment_type="superfluid", payment_types=None, mock_crn_list=None):

    def response_get_program_price(ptype):
        return MagicMock(
            required_tokens=0.00001527777777777777 if ptype == "superfluid" else 1000,
            payment_type=ptype,
        )

    # Create a proper mock for the crn service
    mock_crn_service = MagicMock()
    mock_crn_service.get_crns_list = AsyncMock(return_value={"crns": mock_crn_list or []})

    # Create voucher attributes using the proper types
    from aleph.sdk.types import Voucher, VoucherAttribute

    # Create EVM voucher
    evm_voucher = Voucher(
        id=MOCK_VOUCHER_ID,
        metadata_id=MOCK_METADATA_ID,
        name="EVM Test Voucher",
        description="A test voucher for EVM chains",
        external_url="https://example.com",
        image="https://example.com/image.png",
        icon="https://example.com/icon.png",
        attributes=[
            VoucherAttribute(trait_type="Duration", value="30 days", display_type="string"),
            VoucherAttribute(trait_type="Compute Units", value="4", display_type="number"),
            VoucherAttribute(trait_type="Type", value="instance", display_type="string"),
        ],
    )

    # Create Solana voucher
    solana_voucher = Voucher(
        id="solticket123",
        metadata_id=MOCK_METADATA_ID,
        name="Solana Test Voucher",
        description="A test voucher for Solana",
        external_url="https://example.com",
        image="https://example.com/image.png",
        icon="https://example.com/icon.png",
        attributes=[
            VoucherAttribute(trait_type="Duration", value="60 days", display_type="string"),
            VoucherAttribute(trait_type="Compute Units", value="8", display_type="number"),
            VoucherAttribute(trait_type="Type", value="instance", display_type="string"),
        ],
    )

    # Create a proper mock for voucher service
    mock_voucher_service = MagicMock()
    mock_voucher_service.fetch_vouchers_by_chain = AsyncMock(return_value=[evm_voucher])
    mock_voucher_service.get_vouchers = AsyncMock(return_value=[evm_voucher, solana_voucher])
    mock_voucher_service.get_evm_vouchers = AsyncMock(return_value=[evm_voucher])
    mock_voucher_service.get_solana_vouchers = AsyncMock(return_value=[solana_voucher])

    mock_response_get_message = create_mock_instance_message(mock_account, payg=True)
    mock_response_create_instance = MagicMock(item_hash=FAKE_VM_HASH)

    # Create a proper mock for port_forwarder service
    mock_port_forwarder = MagicMock()
    mock_port_message = MagicMock(item_hash=FAKE_VM_HASH)
    mock_port_forwarder.create_ports = AsyncMock(return_value=(mock_port_message, 200))
    mock_port_forwarder.get_ports = AsyncMock(return_value=None)
    mock_port_forwarder.delete_ports = AsyncMock(return_value=(mock_port_message, 200))

    mock_auth_client = AsyncMock(
        get_messages=AsyncMock(),
        get_message=AsyncMock(return_value=mock_response_get_message),
        create_instance=AsyncMock(return_value=[mock_response_create_instance, 200]),
        get_program_price=None,
        forget=AsyncMock(return_value=(MagicMock(), 200)),
    )

    # Set the service attributes
    mock_auth_client.crn = mock_crn_service
    mock_auth_client.port_forwarder = mock_port_forwarder
    mock_auth_client.voucher = mock_voucher_service

    if payment_types:
        mock_auth_client.get_program_price = AsyncMock(
            side_effect=[response_get_program_price(pt) for pt in payment_types]
        )
    else:
        mock_auth_client.get_program_price = AsyncMock(return_value=response_get_program_price(payment_type))

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


def create_mock_vm_coco_client():
    mock_vm_coco_client = MagicMock(
        get_certificates=AsyncMock(return_value=[200, MagicMock()]),
        create_session=AsyncMock(),
        initialize=AsyncMock(),
        close=AsyncMock(),
        measurement=AsyncMock(return_value="sev_data"),
        validate_measure=AsyncMock(return_value=True),
        build_secret=AsyncMock(return_value=["encoded_packet_header", "encoded_secret"]),
        inject_secret=AsyncMock(),
    )
    mock_vm_coco_client_class = MagicMock(return_value=mock_vm_coco_client)
    return mock_vm_coco_client_class, mock_vm_coco_client


@pytest.mark.parametrize(
    ids=[
        "regular_hold_evm",
        "regular_superfluid_evm",
        "regular_hold_sol",
        "coco_hold_sol",
        "coco_hold_evm",
        "coco_superfluid_evm",
        "gpu_superfluid_evm",
        "nft_payment_avax",
        "nft_payment_base",
        "nft_payment_sol",
    ],
    argnames="args, expected",
    argvalues=[
        (  # regular_hold_evm
            {
                "payment_type": "hold",
                "payment_chain": "ETH",
                "rootfs": "debian12",
                "persistent_volume": ["name=data,mount=/opt/data,size_mib=1000"],
                "ephemeral_volume": ["mount=/opt/tmp,size_mib=100"],
                "immutable_volume": [f"mount=/opt/packages,ref={FAKE_STORE_HASH}"],
            },
            (FAKE_VM_HASH, None, "ETH"),
        ),
        (  # regular_superfluid_evm
            {
                "payment_type": "superfluid",
                "payment_chain": "AVAX",
                "rootfs": "debian12",
                "crn_url": FAKE_CRN_BASIC_URL,
            },
            (FAKE_VM_HASH, FAKE_CRN_BASIC_URL, "AVAX"),
        ),
        (  # regular_hold_sol
            {
                "payment_type": "hold",
                "payment_chain": "SOL",
                "rootfs": "debian12",
            },
            (FAKE_VM_HASH, None, "SOL"),
        ),
        (  # coco_hold_sol
            {
                "payment_type": "hold",
                "payment_chain": "SOL",
                "rootfs": FAKE_STORE_HASH,
                "crn_url": FAKE_CRN_CONF_URL,
                "confidential": True,
            },
            (FAKE_VM_HASH, FAKE_CRN_CONF_URL, "SOL"),
        ),
        (  # coco_hold_evm
            {
                "payment_type": "hold",
                "payment_chain": "ETH",
                "rootfs": FAKE_STORE_HASH,
                "crn_url": FAKE_CRN_CONF_URL,
                "confidential": True,
            },
            (FAKE_VM_HASH, FAKE_CRN_CONF_URL, "ETH"),
        ),
        (  # coco_superfluid_evm
            {
                "payment_type": "superfluid",
                "payment_chain": "BASE",
                "rootfs": FAKE_STORE_HASH,
                "crn_url": FAKE_CRN_CONF_URL,
                "confidential": True,
            },
            (FAKE_VM_HASH, FAKE_CRN_CONF_URL, "BASE"),
        ),
        (  # gpu_superfluid_evm
            {
                "payment_type": "superfluid",
                "payment_chain": "BASE",
                "rootfs": "debian12",
                "crn_url": FAKE_CRN_GPU_URL,
                "gpu": True,
            },
            (FAKE_VM_HASH, FAKE_CRN_GPU_URL, "BASE"),
        ),
        (  # nft_payment_avax
            {
                "payment_type": "nft",
                "payment_chain": "AVAX",
                "rootfs": "debian12",
            },
            (FAKE_VM_HASH, None, "AVAX"),
        ),
        (  # nft_payment_base
            {
                "payment_type": "nft",
                "payment_chain": "BASE",
                "rootfs": "debian12",
                "crn_url": FAKE_CRN_BASIC_URL,
            },
            (FAKE_VM_HASH, None, "BASE"),
        ),
        (  # nft_payment_sol
            {
                "payment_type": "nft",
                "payment_chain": "SOL",
                "rootfs": "debian12",
                "crn_url": FAKE_CRN_BASIC_URL,
            },
            (FAKE_VM_HASH, None, "SOL"),
        ),
    ],
)
@pytest.mark.asyncio
async def test_create_instance(args, expected, mock_crn_list, mock_api_response):
    mock_validate_ssh_pubkey_file = create_mock_validate_ssh_pubkey_file()
    mock_load_account = create_mock_load_account()
    mock_account = mock_load_account.return_value
    mock_get_balance = AsyncMock(return_value={"available_amount": 100000})
    mock_client_class, mock_client = create_mock_client(mock_crn_list, payment_type=args["payment_type"])
    mock_auth_client_class, mock_auth_client = create_mock_auth_client(
        mock_account, payment_type=args["payment_type"], mock_crn_list=mock_crn_list
    )

    mock_vm_client_class, mock_vm_client = create_mock_vm_client()
    mock_validated_prompt = MagicMock(return_value="1")
    mock_fetch_latest_crn_version = create_mock_fetch_latest_crn_version()

    # Create a mock that will properly handle the expected parameters and return a valid CRN info
    mock_yes_no_input = MagicMock(side_effect=[False, True, True])
    mock_wait_for_processed_instance = AsyncMock()
    mock_wait_for_confirmed_flow = AsyncMock()

    @patch("aleph_client.commands.instance.validate_ssh_pubkey_file", mock_validate_ssh_pubkey_file)
    @patch("aleph_client.commands.instance._load_account", mock_load_account)
    @patch("aleph_client.commands.instance.get_balance", mock_get_balance)
    @patch("aleph_client.commands.instance.AlephHttpClient", mock_client_class)
    @patch("aleph_client.commands.instance.AuthenticatedAlephHttpClient", mock_auth_client_class)
    @patch("aleph_client.commands.pricing.validated_prompt", mock_validated_prompt)
    @patch("aleph_client.commands.instance.network.fetch_latest_crn_version", mock_fetch_latest_crn_version)
    @patch("aleph_client.commands.instance.yes_no_input", mock_yes_no_input)
    @patch("aleph_client.commands.instance.wait_for_processed_instance", mock_wait_for_processed_instance)
    @patch("aleph_client.commands.instance.wait_for_confirmed_flow", mock_wait_for_confirmed_flow)
    @patch("aleph_client.commands.instance.VmClient", mock_vm_client_class)
    @patch(
        "aleph_client.commands.instance.network.call_program_crn_list", AsyncMock(return_value={"crns": mock_crn_list})
    )
    @patch("aleph_client.commands.instance.display.CRNTable.run_async", AsyncMock(return_value=(None, 0)))
    @patch("aiohttp.ClientSession.get")
    async def create_instance(mock_get, instance_spec):
        print()  # For better display when pytest -v -s
        # Use the mock_api_response fixture which handles URL-based responses
        mock_get.side_effect = mock_api_response
        all_args = {
            "ssh_pubkey_file": FAKE_PUBKEY_FILE,
            "name": "mock_instance",
            "compute_units": 1,
            "rootfs_size": 0,
            "skip_volume": True,
            "crn_auto_tac": True,
        }
        all_args.update(instance_spec)
        return await create(**all_args)

    returned = await create_instance(instance_spec=args)
    # Basic assertions for all cases
    mock_load_account.assert_called_once()
    mock_validate_ssh_pubkey_file.return_value.read_text.assert_called_once()
    mock_client.get_estimated_price.assert_called_once()
    mock_auth_client.create_instance.assert_called_once()
    # Payment type specific assertions
    if args["payment_type"] == "hold":
        mock_get_balance.assert_called_once()
    elif args["payment_type"] == "superfluid":
        assert mock_account.manage_flow.call_count == 2
        assert mock_wait_for_confirmed_flow.call_count == 2
    # CRN related assertions
    if args["payment_type"] == "superfluid" or args.get("confidential") or args.get("gpu"):
        mock_wait_for_processed_instance.assert_called_once()
        mock_vm_client.start_instance.assert_called_once()
    assert returned == expected


@pytest.mark.asyncio
async def test_list_instances(mock_crn_list):
    mock_load_account = create_mock_load_account()
    mock_account = mock_load_account.return_value
    mock_fetch_latest_crn_version = create_mock_fetch_latest_crn_version()
    mock_client_class, mock_client = create_mock_client(mock_crn_list)
    mock_instance_messages = create_mock_instance_messages(mock_account)
    mock_auth_client_class, mock_auth_client = create_mock_auth_client(
        mock_account,
        payment_types=[vm.content.payment.type for vm in mock_instance_messages.return_value],
        mock_crn_list=mock_crn_list,
    )

    mock_allocations = MagicMock(root={"some_hash": "some_allocation"})
    mock_executions = MagicMock(root={})

    mock_auth_client.instance = MagicMock(
        get_instances=AsyncMock(return_value=mock_instance_messages.return_value),
        get_instances_allocations=AsyncMock(return_value=mock_allocations),
        get_instance_executions_info=AsyncMock(return_value=mock_executions),
    )

    @patch("aleph_client.commands.instance._load_account", mock_load_account)
    @patch("aleph_client.commands.instance.network.fetch_latest_crn_version", mock_fetch_latest_crn_version)
    @patch("aleph_client.commands.files.AlephHttpClient", mock_client_class)
    @patch("aleph_client.commands.instance.AlephHttpClient", mock_auth_client_class)
    @patch("aleph_client.commands.instance.show_instances", AsyncMock())
    async def list_instance():
        print()  # For better display when pytest -v -s
        await list_instances(address=mock_account.get_address())
        mock_auth_client.instance.get_instances.assert_called_once()
        mock_auth_client.instance.get_instances_allocations.assert_called_once()
        mock_auth_client.instance.get_instance_executions_info.assert_called_once()

    await list_instance()


@pytest.mark.asyncio
async def test_delete_instance(mock_api_response):
    mock_load_account = create_mock_load_account()
    mock_account = mock_load_account.return_value
    mock_auth_client_class, mock_auth_client = create_mock_auth_client(mock_account, mock_crn_list=[])
    mock_vm_client_class, mock_vm_client = create_mock_vm_client()
    mock_fetch_settings = AsyncMock(
        return_value={
            "community_wallet_timestamp": 900000,  # Before creation time
            "community_wallet_address": "0xcommunity",
        }
    )

    # Mock port forwarder
    mock_auth_client.port_forwarder = MagicMock(
        get_ports=AsyncMock(return_value=None), delete_ports=AsyncMock(return_value=("mock_message", "mock_status"))
    )

    # We need to mock that there is no CRN information to skip VM erasure
    mock_auth_client.instance = MagicMock(get_instances_allocations=AsyncMock(return_value=MagicMock(root={})))

    @patch("aleph_client.commands.instance._load_account", mock_load_account)
    @patch("aleph_client.commands.instance.AuthenticatedAlephHttpClient", mock_auth_client_class)
    @patch("aleph_client.commands.instance.VmClient", mock_vm_client_class)
    @patch("aleph_client.commands.instance.fetch_settings", mock_fetch_settings)
    @patch.object(asyncio, "sleep", AsyncMock())
    @patch.object(aiohttp.ClientSession, "get")
    async def delete_instance(mock_get):
        print()  # For better display when pytest -v -s
        mock_get.side_effect = mock_api_response
        await delete(FAKE_VM_HASH)
        mock_auth_client.get_message.assert_called_once()
        assert mock_account.manage_flow.call_count == 2
        mock_auth_client.forget.assert_called_once()

    await delete_instance()  # type: ignore[call-arg]


@pytest.mark.asyncio
async def test_delete_instance_with_insufficient_funds():

    mock_load_account = create_mock_load_account()
    mock_account = mock_load_account.return_value

    # Configure manage_flow to raise InsufficientFundsError
    insufficient_funds_error = InsufficientFundsError(
        token_type=TokenType.GAS, required_funds=10.0, available_funds=5.0
    )
    mock_account.manage_flow = AsyncMock(side_effect=insufficient_funds_error)

    mock_auth_client_class, mock_auth_client = create_mock_auth_client(mock_account)
    mock_fetch_vm_info = create_mock_fetch_vm_info()
    mock_vm_client_class, mock_vm_client = create_mock_vm_client()
    mock_fetch_settings = AsyncMock(
        return_value={
            "community_wallet_timestamp": 900000,  # Before creation time
            "community_wallet_address": "0xcommunity",
        }
    )

    @patch("aleph_client.commands.instance._load_account", mock_load_account)
    @patch("aleph_client.commands.instance.AuthenticatedAlephHttpClient", mock_auth_client_class)
    @patch("aleph_client.commands.instance.fetch_vm_info", mock_fetch_vm_info)
    @patch("aleph_client.commands.instance.VmClient", mock_vm_client_class)
    @patch("aleph_client.commands.instance.fetch_settings", mock_fetch_settings)
    @patch.object(asyncio, "sleep", AsyncMock())
    async def delete_instance_with_insufficient_funds():
        print()  # For better display when pytest -v -s
        with pytest.raises(Exit):  # We expect Exit to be raised
            await delete(FAKE_VM_HASH)
        mock_auth_client.get_message.assert_called_once()
        mock_vm_client.erase_instance.assert_called_once()
        mock_account.manage_flow.assert_called_once()  # First manage_flow call raises the error
        mock_auth_client.forget.assert_not_called()  # This should not be called as we exit early

    await delete_instance_with_insufficient_funds()


@pytest.mark.asyncio
async def test_reboot_instance():
    mock_load_account = create_mock_load_account()
    mock_account = mock_load_account.return_value
    mock_auth_client_class, mock_auth_client = create_mock_auth_client(mock_account, mock_crn_list=[])
    mock_vm_client_class, mock_vm_client = create_mock_vm_client()

    # Create a mock for instance allocations
    mock_instance = MagicMock()
    mock_instance.__class__.__name__ = "InstanceWithScheduler"
    mock_instance.allocations = MagicMock()
    mock_instance.allocations.node = MagicMock()
    mock_instance.allocations.node.url = FAKE_CRN_BASIC_URL

    mock_allocation = MagicMock()
    mock_allocation.root = {FAKE_VM_HASH: mock_instance}

    # Add the mock to the auth client
    mock_auth_client.instance = MagicMock(get_instances_allocations=AsyncMock(return_value=mock_allocation))

    @patch("aleph_client.commands.instance._load_account", mock_load_account)
    @patch("aleph_client.commands.instance.network.AlephHttpClient", mock_auth_client_class)
    @patch("aleph_client.commands.instance.VmClient", mock_vm_client_class)
    async def reboot_instance():
        print()  # For better display when pytest -v -s
        await reboot(FAKE_VM_HASH)
        mock_auth_client.get_message.assert_called_once()
        mock_vm_client.reboot_instance.assert_called_once()

    await reboot_instance()


@pytest.mark.asyncio
async def test_allocate_instance():
    mock_load_account = create_mock_load_account()
    mock_account = mock_load_account.return_value
    mock_auth_client_class, mock_auth_client = create_mock_auth_client(mock_account, mock_crn_list=[])
    mock_vm_client_class, mock_vm_client = create_mock_vm_client()

    # Create a mock for instance allocations
    mock_instance = MagicMock()
    mock_instance.__class__.__name__ = "InstanceWithScheduler"
    mock_instance.allocations = MagicMock()
    mock_instance.allocations.node = MagicMock()
    mock_instance.allocations.node.url = FAKE_CRN_BASIC_URL

    mock_allocation = MagicMock()
    mock_allocation.root = {FAKE_VM_HASH: mock_instance}

    # Add the mock to the auth client
    mock_auth_client.instance = MagicMock(get_instances_allocations=AsyncMock(return_value=mock_allocation))

    @patch("aleph_client.commands.instance._load_account", mock_load_account)
    @patch("aleph_client.commands.instance.network.AlephHttpClient", mock_auth_client_class)
    @patch("aleph_client.commands.instance.VmClient", mock_vm_client_class)
    async def allocate_instance():
        print()  # For better display when pytest -v -s
        await allocate(FAKE_VM_HASH)
        mock_auth_client.get_message.assert_called_once()
        mock_vm_client.start_instance.assert_called_once()

    await allocate_instance()


@pytest.mark.asyncio
async def test_logs_instance(capsys):
    mock_load_account = create_mock_load_account()
    mock_account = mock_load_account.return_value
    mock_auth_client_class, mock_auth_client = create_mock_auth_client(mock_account, mock_crn_list=[])
    mock_vm_client_class, mock_vm_client = create_mock_vm_client()

    # Create a mock for instance allocations
    mock_instance = MagicMock()
    mock_instance.__class__.__name__ = "InstanceWithScheduler"
    mock_instance.allocations = MagicMock()
    mock_instance.allocations.node = MagicMock()
    mock_instance.allocations.node.url = FAKE_CRN_BASIC_URL

    mock_allocation = MagicMock()
    mock_allocation.root = {FAKE_VM_HASH: mock_instance}

    # Add the mock to the auth client
    mock_auth_client.instance = MagicMock(get_instances_allocations=AsyncMock(return_value=mock_allocation))

    @patch("aleph_client.commands.instance._load_account", mock_load_account)
    @patch("aleph_client.commands.instance.network.AlephHttpClient", mock_auth_client_class)
    @patch("aleph_client.commands.instance.VmClient", mock_vm_client_class)
    async def logs_instance():
        print()  # For better display when pytest -v -s
        await logs(FAKE_VM_HASH)
        mock_auth_client.get_message.assert_called_once()
        mock_vm_client.get_logs.assert_called_once()

    await logs_instance()
    captured = capsys.readouterr()
    assert captured.out == "\nLog message 1\nLog message 2\n"


@pytest.mark.asyncio
async def test_stop_instance():
    mock_load_account = create_mock_load_account()
    mock_account = mock_load_account.return_value
    mock_auth_client_class, mock_auth_client = create_mock_auth_client(mock_account, mock_crn_list=[])
    mock_vm_client_class, mock_vm_client = create_mock_vm_client()

    # Create a mock for instance allocations
    mock_instance = MagicMock()
    mock_instance.__class__.__name__ = "InstanceWithScheduler"
    mock_instance.allocations = MagicMock()
    mock_instance.allocations.node = MagicMock()
    mock_instance.allocations.node.url = FAKE_CRN_BASIC_URL

    mock_allocation = MagicMock()
    mock_allocation.root = {FAKE_VM_HASH: mock_instance}

    # Add the mock to the auth client
    mock_auth_client.instance = MagicMock(get_instances_allocations=AsyncMock(return_value=mock_allocation))

    @patch("aleph_client.commands.instance._load_account", mock_load_account)
    @patch("aleph_client.commands.instance.network.AlephHttpClient", mock_auth_client_class)
    @patch("aleph_client.commands.instance.VmClient", mock_vm_client_class)
    async def stop_instance():
        print()  # For better display when pytest -v -s
        await stop(FAKE_VM_HASH)
        mock_auth_client.get_message.assert_called_once()
        mock_vm_client.stop_instance.assert_called_once()

    await stop_instance()


@pytest.mark.asyncio
async def test_confidential_init_session():
    mock_load_account = create_mock_load_account()
    mock_account = mock_load_account.return_value
    mock_auth_client_class, mock_auth_client = create_mock_auth_client(mock_account, mock_crn_list=[])
    mock_shutil = create_mock_shutil()
    mock_vm_coco_client_class, mock_vm_coco_client = create_mock_vm_coco_client()

    # Create a mock for instance allocations
    mock_instance = MagicMock()
    mock_instance.__class__.__name__ = "InstanceWithScheduler"
    mock_instance.allocations = MagicMock()
    mock_instance.allocations.node = MagicMock()
    mock_instance.allocations.node.url = FAKE_CRN_CONF_URL

    mock_allocation = MagicMock()
    mock_allocation.root = {FAKE_VM_HASH: mock_instance}

    # Add the mock to the auth client
    mock_auth_client.instance = MagicMock(get_instances_allocations=AsyncMock(return_value=mock_allocation))

    @patch("aleph_client.commands.instance._load_account", mock_load_account)
    @patch("aleph_client.commands.instance.network.AlephHttpClient", mock_auth_client_class)
    @patch("aleph_client.commands.utils.shutil", mock_shutil)
    @patch("aleph_client.commands.instance.shutil", mock_shutil)
    @patch.object(Path, "exists", MagicMock(return_value=True))
    @patch("aleph_client.commands.instance.VmConfidentialClient", mock_vm_coco_client_class)
    async def coco_init_session():
        print()  # For better display when pytest -v -s
        await confidential_init_session(FAKE_VM_HASH, keep_session=False)
        mock_shutil.which.assert_called_once()
        mock_auth_client.get_message.assert_called_once()
        mock_vm_coco_client.get_certificates.assert_called_once()
        mock_shutil.move.assert_called_once()
        mock_vm_coco_client.create_session.assert_called_once()
        mock_vm_coco_client.initialize.assert_called_once()
        mock_vm_coco_client.close.assert_called_once()

    await coco_init_session()


@pytest.mark.asyncio
async def test_confidential_start():
    mock_load_account = create_mock_load_account()
    mock_account = mock_load_account.return_value
    mock_shutil = create_mock_shutil()
    mock_auth_client_class, mock_auth_client = create_mock_auth_client(mock_account, mock_crn_list=[])
    mock_vm_coco_client_class, mock_vm_coco_client = create_mock_vm_coco_client()
    mock_calculate_firmware_hash = MagicMock(return_value=FAKE_STORE_HASH)

    # Create a mock for instance allocations
    mock_instance = MagicMock()
    mock_instance.__class__.__name__ = "InstanceWithScheduler"
    mock_instance.allocations = MagicMock()
    mock_instance.allocations.node = MagicMock()
    mock_instance.allocations.node.url = FAKE_CRN_CONF_URL

    mock_allocation = MagicMock()
    mock_allocation.root = {FAKE_VM_HASH: mock_instance}

    # Add the mock to the auth client
    mock_auth_client.instance = MagicMock(get_instances_allocations=AsyncMock(return_value=mock_allocation))

    @patch("aleph_client.commands.instance._load_account", mock_load_account)
    @patch("aleph_client.commands.utils.shutil", mock_shutil)
    @patch("aleph_client.commands.instance.network.AlephHttpClient", mock_auth_client_class)
    @patch.object(Path, "exists", MagicMock(return_value=True))
    @patch.object(Path, "mkdir", MagicMock())
    @patch("aleph_client.commands.instance.VmConfidentialClient", mock_vm_coco_client_class)
    @patch("aleph_client.commands.instance.calculate_firmware_hash", mock_calculate_firmware_hash)
    async def coco_start():
        print()  # For better display when pytest -v -s
        await confidential_start(FAKE_VM_HASH, firmware_file="/fake/file", vm_secret="fake_secret")
        mock_auth_client.get_message.assert_called_once()
        mock_vm_coco_client.measurement.assert_called_once()
        mock_calculate_firmware_hash.assert_called_once()
        mock_vm_coco_client.validate_measure.assert_called_once()
        mock_vm_coco_client.build_secret.assert_called_once()
        mock_vm_coco_client.inject_secret.assert_called_once()
        mock_vm_coco_client.close.assert_called_once()

    await coco_start()


@pytest.mark.parametrize(
    ids=[
        "coco_from_scratch",
        "coco_from_hash",
    ],
    argnames="args",
    argvalues=[
        {  # coco_from_scratch
            "payment_type": "superfluid",
            "payment_chain": "AVAX",
            "crn_url": FAKE_CRN_CONF_URL,
            "rootfs": FAKE_STORE_HASH,
            "compute_units": 1,
        },
        {"vm_id": FAKE_VM_HASH, "crn_url": FAKE_CRN_CONF_URL},  # Add crn_url to avoid find_crn_of_vm call
    ],
)
@pytest.mark.asyncio
async def test_confidential_create(mock_crn_list, args):
    mock_load_account = create_mock_load_account()
    mock_account = mock_load_account.return_value
    mock_shutil = create_mock_shutil()
    mock_create = AsyncMock(return_value=[FAKE_VM_HASH, FAKE_CRN_CONF_URL, "AVAX"])
    mock_auth_client_class, mock_auth_client = create_mock_auth_client(mock_account, mock_crn_list=[])
    mock_client_class, mock_client = create_mock_client(mock_crn_list)
    # Removed unused mock_fetch_vm_info
    mock_allocate = AsyncMock(return_value=None)
    mock_confidential_init_session = AsyncMock(return_value=None)
    mock_confidential_start = AsyncMock()

    # Create a mock for instance allocations
    mock_instance = MagicMock()
    mock_instance.__class__.__name__ = "InstanceWithScheduler"
    mock_instance.allocations = MagicMock()
    mock_instance.allocations.node = MagicMock()
    mock_instance.allocations.node.url = FAKE_CRN_CONF_URL

    mock_allocation = MagicMock()
    mock_allocation.root = {FAKE_VM_HASH: mock_instance}

    # Add the mock to the auth client
    mock_auth_client.instance = MagicMock(get_instances_allocations=AsyncMock(return_value=mock_allocation))

    @patch("aleph_client.commands.utils.shutil", mock_shutil)
    @patch("aleph_client.commands.instance.create", mock_create)
    @patch("aleph_client.commands.instance.AlephHttpClient", mock_auth_client_class)
    @patch("aleph_client.commands.instance.network.AlephHttpClient", mock_client_class)
    @patch("aleph_client.commands.instance.allocate", mock_allocate)
    @patch("aleph_client.commands.instance.confidential_init_session", mock_confidential_init_session)
    @patch.object(asyncio, "sleep", AsyncMock())
    @patch("aleph_client.commands.instance.confidential_start", mock_confidential_start)
    async def coco_create(instance_spec):
        print()  # For better display when pytest -v -s
        all_args = {
            "ssh_pubkey_file": FAKE_PUBKEY_FILE,
            "name": "mock_instance",
            "compute_units": 1,
            "rootfs_size": 0,
            "skip_volume": True,
            "crn_auto_tac": True,
            "keep_session": False,
            "vm_secret": "fake_secret",
        }
        all_args.update(instance_spec)
        await confidential_create(**all_args)

    await coco_create(args)
    mock_shutil.which.assert_called_once()
    mock_confidential_init_session.assert_called_once()
    mock_confidential_start.assert_called_once()


@pytest.mark.asyncio
async def test_gpu_create():
    mock_create = AsyncMock(return_value=[FAKE_VM_HASH, FAKE_CRN_GPU_URL, "AVAX"])

    @patch("aleph_client.commands.instance.create", mock_create)
    async def gpu_instance():
        print()  # For better display when pytest -v -s
        await gpu_create()
        mock_create.assert_called_once()

    await gpu_instance()
