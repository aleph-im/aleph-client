import typer
from pathlib import Path
from enum import Enum
import logging
from pathlib import Path
from .firecracker import download_firecracker
from .templates import download_templates
import os
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
    if os.path.exists(dest):
        if not os.path.isdir(dest):
            print(f"destination path '{dest}' already exists and is not a directory.", file=stderr)
            exit(1)
        if os.listdir(dest):
            print(f"destination path '{dest}' already exists and is not an empty directory.", file=stderr)
            exit(1)
    os.makedirs(dest, exist_ok=True)
    download_firecracker(dest)
    download_templates(dest, sdk_version)

@app.command()
def build(
    project: Path = typer.Argument(..., help="The name of your project"),
    test: bool = typer.Option(False, help="Build a test runtime to test your plugins locally"),
    builder: BuilderOption = typer.Option(BuilderOption.podman, help="Choose between docker and podman to build your runtime"),
    version: str = typer.Option("latest", help="tag of your runtime version")
):
    """Build a runtime created with the init command, using podman or docker"""
    image_name = f"{project}:{version}"
    context = f"{project}/plugins"
    containerfile = f"{project}/plugins/Containerfile"
    os.system(f"{builder} build -f {containerfile} -t {image_name} {context}")
    os.system(f"{builder} container create --name {project} {image_name}")
    os.makedirs(f"{project}/build", exist_ok=True)
    os.system(f"{builder} export {project} > {project}/build/rootfs.tar")
    os.makedirs(f"{project}/build/rootfs", exist_ok=True)
    os.system(f"tar -xf {project}/build/rootfs.tar --directory={project}/build/rootfs")
    os.system(f"{builder} container rm {project}")
    os.system(f"mksquashfs {project}/build/rootfs {project}/build/rootfs.squashfs")



