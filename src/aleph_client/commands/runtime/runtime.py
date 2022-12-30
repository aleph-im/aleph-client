import typer
from pathlib import Path
from enum import Enum
import logging
from pathlib import Path
from .firecracker import download_firecracker
from .templates import download_templates
from os import makedirs, listdir
from os import path
from sys import stderr

import typer

logger = logging.getLogger(__name__)
app = typer.Typer()


class BuilderOption(str, Enum):
    docker = "docker"
    podman = "podman"



app = typer.Typer()


@app.command()
def init(
    dest: Path = typer.Argument(..., help="The name of your project"),
    sdk_version: str = typer.Option("latest")
):
    """Init a project with folder architecture and tools"""
    if path.exists(dest):
        if not path.isdir(dest):
            print(f"destination path '{dest}' already exists and is not a directory.", file=stderr)
            exit(1)
        if listdir(dest):
            print(f"destination path '{dest}' already exists and is not an empty directory.", file=stderr)
            exit(1)
    makedirs(dest, exist_ok=True)
    download_firecracker(dest)
    download_templates(dest, sdk_version)

@app.command()
def build(
    path: Path = typer.Argument(..., help="The name of your project"),
    test: bool = typer.Option(False, help="Build a test runtime to test your plugins locally"),
    builder: BuilderOption = typer.Option(BuilderOption.podman, help="Choose between docker and podman to build your runtime")
):
    """Build a runtime created with the init command, using podman or docker"""

