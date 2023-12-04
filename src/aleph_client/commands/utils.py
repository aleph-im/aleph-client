import logging
from datetime import datetime
from typing import Callable, Dict, List, Optional, TypeVar, Union

import typer
from aleph.sdk.types import GenericMessage
from pygments import highlight
from pygments.formatters.terminal256 import Terminal256Formatter
from pygments.lexers import JsonLexer
from typer import echo


def colorful_json(obj: str):
    """Render a JSON string with colors."""
    return highlight(
        obj,
        lexer=JsonLexer(),
        formatter=Terminal256Formatter(),
    )


def colorful_message_json(message: GenericMessage):
    """Render a message in JSON with colors."""
    return colorful_json(message.json(sort_keys=True, indent=4))


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


def yes_no_input(text: str, default: Optional[bool] = None):
    while True:
        if default is True:
            response = input(f"{text} [Y/n] ")
        elif default is False:
            response = input(f"{text} [y/N] ")
        else:
            response = input(f"{text} ")

        if response.lower() in ("y", "yes"):
            return True
        elif response.lower() in ("n", "no"):
            return False
        elif response == "" and default is not None:
            return default
        else:
            if default is None:
                echo("Please enter 'y', 'yes', 'n' or 'no'")
            else:
                echo("Please enter 'y', 'yes', 'n', 'no' or nothing")
            continue


def prompt_for_volumes():
    while yes_no_input("Add volume ?", default=False):
        comment = input("Description: ") or None
        mount = input("Mount: ")
        persistent = yes_no_input("Persist on VM host ?", default=False)
        if persistent:
            name = input("Volume name: ")
            size_mib = int(input("Size in MiB: "))
            yield {
                "comment": comment,
                "mount": mount,
                "name": name,
                "persistence": "host",
                "size_mib": size_mib,
            }
        else:
            ref = input("Ref: ")
            use_latest = yes_no_input("Use latest version ?", default=True)
            yield {
                "comment": comment,
                "mount": mount,
                "ref": ref,
                "use_latest": use_latest,
            }


def volume_to_dict(volume: List[str]) -> Optional[Dict[str, Union[str, int]]]:
    if not volume:
        return None
    dict_store: Dict[str, Union[str, int]] = {}
    for word in volume:
        split_values = word.split(",")
        for param in split_values:
            p = param.split("=")
            if p[1].isdigit():
                dict_store[p[0]] = int(p[1])
            elif p[1] in ["True", "true", "False", "false"]:
                dict_store[p[0]] = bool(p[1].capitalize())
            else:
                dict_store[p[0]] = p[1]

    return dict_store


def get_or_prompt_volumes(ephemeral_volume, immutable_volume, persistent_volume):
    volumes = []
    # Check if the volumes are empty
    if (
        persistent_volume is None
        or ephemeral_volume is None
        or immutable_volume is None
    ):
        for volume in prompt_for_volumes():
            volumes.append(volume)
            typer.echo("\n")

    # else parse all the volumes that have passed as the cli parameters and put it into volume list
    else:
        if len(persistent_volume) > 0:
            persistent_volume_dict = volume_to_dict(volume=persistent_volume)
            volumes.append(persistent_volume_dict)
        if len(ephemeral_volume) > 0:
            ephemeral_volume_dict = volume_to_dict(volume=ephemeral_volume)
            volumes.append(ephemeral_volume_dict)
        if len(immutable_volume) > 0:
            immutable_volume_dict = volume_to_dict(volume=immutable_volume)
            volumes.append(immutable_volume_dict)
    return volumes


def str_to_datetime(date: Optional[str]) -> Optional[datetime]:
    """
    Converts a string representation of a date/time to a datetime object.

    The function can accept either a timestamp or an ISO format datetime string as the input.
    """
    if date is None:
        return None
    try:
        date_f = float(date)
        return datetime.fromtimestamp(date_f)
    except ValueError:
        pass
    return datetime.fromisoformat(date)


T = TypeVar("T")


def default_prompt(
    prompt: str,
    default: str,
) -> str:
    return input(prompt + (f" [default: {default}]" if default else "")) or default


def validated_prompt(
    prompt: str,
    validator: Callable[[str], T],
    default: Optional[T] = None,
) -> T:
    while True:
        value = input(prompt + (f" [default: {default}]" if default else ""))
        if value == "" and default is not None:
            return default
        try:
            return validator(value)
        except ValueError as e:
            echo(f"Invalid input: {e}\nTry again.")
            continue


def validated_int_prompt(
    prompt: str,
    default: Optional[int] = None,
    min_value: Optional[int] = None,
    max_value: Optional[int] = None,
) -> int:
    def validator(value: str) -> int:
        value = int(value)
        if min_value is not None and value < min_value:
            raise ValueError(f"Value must be greater than or equal to {min_value}")
        if max_value is not None and value > max_value:
            raise ValueError(f"Value must be less than or equal to {max_value}")
        return value

    return validated_prompt(prompt, validator, default)
