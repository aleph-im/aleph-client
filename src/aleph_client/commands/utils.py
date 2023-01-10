import logging
from typer import echo
from typing import Optional, List, Dict, Union


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
            elif p[1] in ['True', 'true', 'False', 'false']:
                dict_store[p[0]] = bool(p[1].capitalize())
            else:
                dict_store[p[0]] = p[1]

    return dict_store

