from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar, Union, get_args

from aiohttp import ClientSession
from aleph.sdk import AlephHttpClient
from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.conf import settings
from aleph.sdk.exceptions import ForgottenMessageError, MessageNotFoundError
from aleph.sdk.types import GenericMessage
from aleph.sdk.utils import safe_getattr
from aleph_message.models import AlephMessage, InstanceMessage, ItemHash, ProgramMessage
from aleph_message.models.execution.volume import (
    EphemeralVolumeSize,
    PersistentVolumeSizeMib,
)
from aleph_message.status import MessageStatus
from pydantic.fields import FieldInfo
from pygments import highlight
from pygments.formatters.terminal256 import Terminal256Formatter
from pygments.lexers import JsonLexer
from rich.prompt import IntPrompt, Prompt, PromptError
from typer import Exit, colors, echo, style

from aleph_client.utils import fetch_json

logger = logging.getLogger(__name__)


def colorful_json(obj: str):
    """Render a JSON string with colors."""
    return highlight(
        obj,
        lexer=JsonLexer(),
        formatter=Terminal256Formatter(),
    )


def colorized_status(status: MessageStatus) -> str:
    """Return a colored status string based on its value."""
    status_colors = {
        MessageStatus.REJECTED: colors.RED,
        MessageStatus.PROCESSED: colors.GREEN,
        MessageStatus.PENDING: colors.YELLOW,
        MessageStatus.FORGOTTEN: colors.BRIGHT_BLACK,
    }
    color = status_colors.get(status, colors.WHITE)
    return style(status, fg=color, bold=True)


def colorful_message_json(message: GenericMessage):
    """Render a message in JSON with colors."""
    return colorful_json(json.dumps(message.model_dump(), sort_keys=True, indent=4))


def input_multiline() -> str:
    """Prompt the user for a multiline input."""
    echo("Enter/Paste your content. Ctrl-D or Ctrl-Z ( windows ) to save it.")
    contents = ""
    while True:
        try:
            line = input()
        except EOFError:
            break
        contents += line + "\n"
    return contents


def setup_logging(debug: bool = False):
    level = logging.DEBUG if debug else logging.WARNING
    logging.basicConfig(level=level)


def yes_no_input(text: str, default: str | bool) -> bool:
    return (
        Prompt.ask(text, choices=["y", "n"], default=default if isinstance(default, str) else ("y" if default else "n"))
        == "y"
    )


def is_valid_mount_path(mount: str) -> bool:
    return mount.startswith("/") and len(mount) > 1


def get_annotated_constraint(annotated_type: type, constraint_name: str) -> Any | None:
    """
    Extract the constraint values from annotated types.
    """
    args = get_args(annotated_type)
    if not args:
        return None

    for arg in args:
        if isinstance(arg, FieldInfo):
            value = getattr(arg, constraint_name, None)
            return value
    return None


def prompt_for_volumes():
    while yes_no_input("Add volume?", default=False):
        mount = validated_prompt("Mount path (must be absolute, ex: /opt/data)", is_valid_mount_path)
        comment = Prompt.ask("Comment (description)")
        base_volume = {"mount": mount, "comment": comment}

        if yes_no_input("Use an immutable volume?", default=False):
            ref = validated_prompt("Item hash", lambda text: len(text) == 64)
            use_latest = yes_no_input("Use latest version?", default=True)
            yield {
                **base_volume,
                "ref": ref,
                "use_latest": use_latest,
            }
        elif yes_no_input("Persist on VM host?", default=False):
            parent = None
            if yes_no_input("Copy from a parent volume?", default=False):
                parent = {"ref": validated_prompt("Item hash", lambda text: len(text) == 64), "use_latest": True}
            name = validated_prompt("Name", lambda text: len(text) > 0)
            min_size = get_annotated_constraint(PersistentVolumeSizeMib, "gt") or 0
            max_size = get_annotated_constraint(PersistentVolumeSizeMib, "le") or 0
            size_mib = validated_int_prompt(
                "Size (MiB)",
                min_value=min_size + 1,
                max_value=max_size,
            )
            yield {
                **base_volume,
                "parent": parent,
                "persistence": "host",
                "name": name,
                "size_mib": size_mib,
            }
        else:  # Ephemeral
            min_size = get_annotated_constraint(EphemeralVolumeSize, "gt") or 0
            max_size = get_annotated_constraint(EphemeralVolumeSize, "le") or 0
            size_mib = validated_int_prompt("Size (MiB)", min_value=min_size + 1, max_value=max_size)
            yield {
                **base_volume,
                "ephemeral": True,
                "size_mib": size_mib,
            }


def volume_to_dict(volume: Optional[str]) -> Optional[dict[str, Union[str, int]]]:
    if not volume:
        return None
    dict_store: dict[str, Union[str, int]] = {}
    split_values = volume.split(",")
    for param in split_values:
        p = param.split("=")
        if p[1].isdigit():
            dict_store[p[0]] = int(p[1])
        elif p[1].lower() in ["true", "false"]:
            dict_store[p[0]] = bool(p[1].capitalize())
        else:
            dict_store[p[0]] = p[1]
    if "mount" not in dict_store or not is_valid_mount_path(str(dict_store["mount"])):
        echo(f"Missing or invalid 'mount' path in volume: {volume}")
        dict_store["mount"] = validated_prompt("Mount path (must be absolute, ex: /opt/data)", is_valid_mount_path)
    return dict_store


def get_or_prompt_volumes(
    ephemeral_volume: Optional[list[str]], immutable_volume: Optional[list[str]], persistent_volume: Optional[list[str]]
):
    volumes = []
    # Check if the volumes are empty
    if not any([persistent_volume, ephemeral_volume, immutable_volume]):
        for volume in prompt_for_volumes():
            volumes.append(volume)

    # else parse all the volumes that have passed as the cli parameters and put it into volume list
    else:
        if persistent_volume:
            for volume in persistent_volume:
                persistent_volume_dict = volume_to_dict(volume=volume)
                if persistent_volume_dict:
                    persistent_volume_dict.update({"persistence": "host"})
                    volumes.append(persistent_volume_dict)
        if ephemeral_volume:
            for volume in ephemeral_volume:
                ephemeral_volume_dict = volume_to_dict(volume=volume)
                if ephemeral_volume_dict:
                    volumes.append(ephemeral_volume_dict)
        if immutable_volume:
            for volume in immutable_volume:
                immutable_volume_dict = volume_to_dict(volume=volume)
                if immutable_volume_dict:
                    volumes.append(immutable_volume_dict)
    return volumes


def display_mounted_volumes(message: Union[InstanceMessage, ProgramMessage]) -> str:
    volumes = ""
    if message.content.volumes:
        for volume in message.content.volumes:
            ref = safe_getattr(volume, "ref")
            size_mib = safe_getattr(volume, "size_mib")
            if ref:
                volumes += (
                    f"\n[deep_sky_blue1]• {volume.mount} ➜ immutable: [/deep_sky_blue1][bright_cyan]"
                    f"[link={settings.API_HOST}/api/v0/messages/{ref}]{ref}[/link][/bright_cyan]"
                )
            elif safe_getattr(volume, "ephemeral"):
                volumes += (
                    f"\n[deep_sky_blue1]• {volume.mount} ➜ [/deep_sky_blue1]"
                    f"[orange3]ephemeral: {size_mib} MiB[/orange3]"
                )
            else:
                volumes += (
                    f"\n[deep_sky_blue1]• {volume.mount} ➜ [/deep_sky_blue1]"
                    f"[orchid]persistent: {size_mib} MiB[/orchid]"
                )
    return f"\nMounted Volumes: {volumes if volumes else '-'}"


def env_vars_to_dict(env_vars: Optional[str]) -> dict[str, str]:
    dict_store: dict[str, str] = {}
    if env_vars:
        for env_var in env_vars.split(","):
            label, value = env_var.split("=", 1)
            dict_store[label.strip()] = value.strip()
    return dict_store


def get_or_prompt_environment_variables(env_vars: Optional[str]) -> Optional[dict[str, str]]:
    environment_variables: dict[str, str] = {}
    if not env_vars:
        while yes_no_input("Add environment variable?", default=False):
            label = validated_prompt("Label: ", lambda text: len(text) > 0)
            value = validated_prompt("Value: ", lambda text: len(text) > 0)
            environment_variables[label] = value
    else:
        environment_variables = env_vars_to_dict(env_vars)
    return environment_variables if environment_variables else None


def str_to_datetime(date: Optional[str]) -> Optional[datetime]:
    """
    Converts a string representation of a date/time to a datetime object in local time.

    The function can accept either a timestamp or an ISO format datetime string as the input.
    """
    if date is None:
        return None
    try:
        date_f = float(date)
        utc_dt = datetime.fromtimestamp(date_f, tz=timezone.utc)
        return utc_dt.astimezone()
    except ValueError:
        dt = datetime.fromisoformat(date)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone()


T = TypeVar("T")


def validated_prompt(
    prompt: str,
    validator: Callable[[str], Any],
    default: Optional[str] = None,
) -> str:
    value = ""
    while True:
        try:
            value = (
                Prompt.ask(
                    prompt,
                    default=default,
                )
                if default is not None
                else Prompt.ask(prompt)
            )
        except PromptError:
            echo(f"Invalid input: {value}\nTry again.")
            continue
        if value is None and default is not None:
            return default
        if validator(str(value)):
            return str(value)
        echo(f"Invalid input: {value}\nTry again.")


def validated_int_prompt(
    prompt: str,
    default: Optional[int] = None,
    min_value: Optional[int] = None,
    max_value: Optional[int] = None,
) -> int:
    value = None
    while True:
        try:
            value = IntPrompt.ask(
                prompt + f" [orange1]<min: {min_value or '-'}, max: {max_value or '-'}>[/orange1]",
                default=default,
            )
        except PromptError:
            echo(f"Invalid input: {value}\nTry again.")
            continue
        if value is None:
            if default is not None:
                return default
            else:
                value = 0
        if min_value is not None and value < min_value:
            echo(f"Invalid input: {value}\nTry again.")
            continue
        if max_value is not None and value > max_value:
            echo(f"Invalid input: {value}\nTry again.")
            continue
        return value


def is_environment_interactive() -> bool:
    """
    Check if the current environment is interactive and can answer questions.
    """
    return all(
        (
            sys.stdin.isatty(),
            sys.stdout.isatty(),
            not os.environ.get("CI", False),
            not os.environ.get("DEBIAN_NONINTERACTIVE") == "noninteractive",
        )
    )


async def wait_for_processed_instance(session: ClientSession, item_hash: ItemHash):
    """Wait for a message to be processed by CCN"""
    while True:
        url = f"{settings.API_HOST.rstrip('/')}/api/v0/messages/{item_hash}"
        message = await fetch_json(session, url)
        if message["status"] == "processed":
            return
        elif message["status"] == "pending":
            echo(f"Message {item_hash} is still pending, waiting 10sec...")
            await asyncio.sleep(10)
        elif message["status"] == "rejected":
            msg = f"Message {item_hash} has been rejected"
            raise Exception(msg)


async def wait_for_confirmed_flow(account: ETHAccount, receiver: str):
    """Wait for a flow to be confirmed on-chain"""
    while True:
        flow = await account.get_flow(receiver)
        if flow:
            return
        echo("Flow transaction is still pending, waiting 10sec...")
        await asyncio.sleep(10)


async def filter_only_valid_messages(messages: list[AlephMessage]):
    """Iteratively check the status of each message from the API and only return
    messages whose status is processed.
    """
    filtered_messages = []
    async with AlephHttpClient(api_server=settings.API_HOST) as client:
        for message in messages:
            item_hash: ItemHash = message.item_hash
            try:
                msg = await client.get_message(ItemHash(item_hash))
                filtered_messages.append(msg)
            except MessageNotFoundError:
                logger.debug("Message not found %s", item_hash)
            except ForgottenMessageError:
                logger.debug("Message not found %s", item_hash)
        return filtered_messages


def validate_ssh_pubkey_file(file: Union[str, Path]) -> Path:
    if isinstance(file, str):
        file = Path(file).expanduser()
    if not file.exists():
        msg = f"{file} does not exist"
        raise ValueError(msg)
    if not file.is_file():
        msg = f"{file} is not a file"
        raise ValueError(msg)
    return file


def find_sevctl_or_exit() -> Path:
    "Find sevctl in path, exit with message if not available"
    sevctl_path = shutil.which("sevctl")
    if sevctl_path is None:
        echo("sevctl binary is not available. Please install sevctl, ensure it is in the PATH and try again.")
        echo("Instructions for setup https://docs.aleph.im/computing/confidential/requirements/")
        raise Exit(code=1)
    return Path(sevctl_path)


def found_gpus_by_model(crn_list: list) -> dict[str, dict[str, dict[str, int]]]:
    found_gpu_models: dict[str, dict[str, dict[str, int]]] = {}
    for crn_ in crn_list:
        found_gpus: dict[str, dict[str, dict[str, int]]] = {}
        for gpu_ in crn_.compatible_available_gpus:
            model = gpu_["model"]
            device = gpu_["device_name"]
            if model not in found_gpus:
                found_gpus[model] = {device: {"count": 1, "on_crns": 1}}
            elif device not in found_gpus[model]:
                found_gpus[model][device] = {"count": 1, "on_crns": 1}
            else:
                found_gpus[model][device]["count"] += 1
        for model, devices in found_gpus.items():
            if model not in found_gpu_models:
                found_gpu_models[model] = devices
            else:
                for device, details in devices.items():
                    if device not in found_gpu_models[model]:
                        found_gpu_models[model][device] = details
                    else:
                        found_gpu_models[model][device]["count"] += details["count"]
                        found_gpu_models[model][device]["on_crns"] += details["on_crns"]
    return found_gpu_models
