from pathlib import Path

import pytest
import typer
from aleph.sdk.conf import AccountType, MainConfiguration
from aleph_message.models import (
    AggregateMessage,
    Chain,
    ForgetMessage,
    PostMessage,
    ProgramMessage,
    StoreMessage,
)
from aleph_message.models.base import MessageType

from aleph_client.commands.utils import validate_non_interactive_args_config
from aleph_client.utils import get_message_type_value


def test_get_message_type_value():
    assert get_message_type_value(PostMessage) == MessageType.post
    assert get_message_type_value(AggregateMessage) == MessageType.aggregate
    assert get_message_type_value(StoreMessage) == MessageType.store
    assert get_message_type_value(ProgramMessage) == MessageType.program
    assert get_message_type_value(ForgetMessage) == MessageType.forget


@pytest.fixture
def hardware_config():
    return MainConfiguration(
        path=None,
        chain=Chain.ETH,
        address="0xHARDWARE",
        type=AccountType.HARDWARE,
    )


@pytest.fixture
def imported_config():
    return MainConfiguration(
        path=Path("/tmp/existing.key"),  # noqa: S108
        chain=Chain.ETH,
        address=None,
        type=AccountType.IMPORTED,
    )


@pytest.mark.parametrize(
    "kwargs,exit_code",
    [
        # RULE 1: hardware requires address or derivation path
        (
            {
                "config": None,
                "account_type": AccountType.HARDWARE,
                "private_key_file": None,
                "address": None,
                "chain": None,
                "derivation_path": None,
            },
            1,
        ),
        # RULE 2: imported requires private key
        (
            {
                "config": None,
                "account_type": AccountType.IMPORTED,
                "private_key_file": None,
                "address": None,
                "chain": None,
                "derivation_path": None,
            },
            1,
        ),
        # RULE 3: cannot specify address + private key
        (
            {
                "config": None,
                "account_type": None,
                "private_key_file": Path("fake.key"),
                "address": "0x123",
                "chain": None,
                "derivation_path": None,
            },
            1,
        ),
        # RULE 8: no args - exit(0)
        (
            {
                "config": None,
                "account_type": None,
                "private_key_file": None,
                "address": None,
                "chain": None,
                "derivation_path": None,
            },
            0,
        ),
    ],
)
def test_validate_non_interactive_negative_cases(kwargs, exit_code):
    with pytest.raises(typer.Exit) as exc:
        validate_non_interactive_args_config(**kwargs)
    assert exc.value.exit_code == exit_code


@pytest.mark.parametrize(
    "override_kwargs,exit_code",
    [
        # RULE 4: private key invalid for hardware (existing HW config)
        ({"private_key_file": Path("k.key")}, 1),
        # RULE 5: address invalid for imported config
        ({"address": "0x123"}, 1),
        # RULE 6: derivation path invalid for imported config
        ({"derivation_path": "44'/60'/0'/0/0"}, 1),
    ],
)
def test_validate_non_interactive_invalid_with_existing_config(
    override_kwargs, exit_code, hardware_config, imported_config
):
    """
    This test runs twice:
    - once with hardware_config
    - once with imported_config

    And applies the override on top.
    """

    # HW-config cases: only RULE 4 applies
    if override_kwargs.get("private_key_file"):
        config = hardware_config
    else:
        config = imported_config

    base_kwargs = {
        "config": config,
        "account_type": None,
        "private_key_file": None,
        "address": None,
        "chain": None,
        "derivation_path": None,
    }

    kwargs = {**base_kwargs, **override_kwargs}

    with pytest.raises(typer.Exit) as exc:
        validate_non_interactive_args_config(**kwargs)

    assert exc.value.exit_code == exit_code


@pytest.mark.parametrize(
    "kwargs",
    [
        # Hardware OK with address
        {
            "config": None,
            "account_type": AccountType.HARDWARE,
            "private_key_file": None,
            "address": "0x123",
            "chain": None,
            "derivation_path": None,
        },
        # Hardware OK with derivation path
        {
            "config": None,
            "account_type": AccountType.HARDWARE,
            "private_key_file": None,
            "address": None,
            "chain": None,
            "derivation_path": "44'/60'/0'/0/0",
        },
        # Imported OK with private key
        {
            "config": None,
            "account_type": AccountType.IMPORTED,
            "private_key_file": Path("/tmp/key.key"),  # noqa: S108
            "address": None,
            "chain": None,
            "derivation_path": None,
        },
        # Chain updates always allowed
        {
            "config": None,
            "account_type": None,
            "private_key_file": None,
            "address": None,
            "chain": Chain.ETH,
            "derivation_path": None,
        },
    ],
)
def test_validate_non_interactive_valid_cases(kwargs):
    """These should not raise."""
    validate_non_interactive_args_config(**kwargs)
