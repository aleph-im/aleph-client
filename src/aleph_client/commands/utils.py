import logging
from datetime import datetime
from typing import Callable, Dict, List, Optional, TypeVar, Union, Any

import typer
from aleph.sdk.types import GenericMessage
from pygments import highlight
from pygments.formatters.terminal256 import Terminal256Formatter
from pygments.lexers import JsonLexer
from rich.prompt import IntPrompt, Prompt, PromptError
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


def yes_no_input(text: str, default: bool) -> bool:
    return Prompt.ask(text, choices=["y", "n"], default=default) == "y"


def prompt_for_volumes():
    while yes_no_input("Add volume ?", default=False):
        mount = Prompt.ask("Mount path: ")
        comment = Prompt.ask("Comment: ")
        persistent = yes_no_input("Persist on VM host?", default=False)
        if persistent:
            name = Prompt.ask("Name: ")
            size_mib = validated_int_prompt("Size (MiB): ", min_value=1)
            yield {
                "comment": comment,
                "mount": mount,
                "name": name,
                "persistence": "host",
                "size_mib": size_mib,
            }
        else:
            ref = Prompt.ask("Item hash: ")
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


def validated_prompt(
    prompt: str,
    validator: Callable[[str], Any],
    default: Optional[str] = None,
) -> str:
    while True:
        try:
            value = Prompt.ask(
                prompt,
                default=default,
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
    while True:
        try:
            value = IntPrompt.ask(
                prompt + f" [min: {min_value or '-'}, max: {max_value or '-'}]",
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
