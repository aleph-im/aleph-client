import typer
from pathlib import Path
from enum import Enum
import logging
from pathlib import Path
from .init_command.download_firecracker import download_firecracker
from .init_command.download_templates import download_templates
import os
from sys import stderr
import subprocess
import sys
import time
import signal
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

def build_runtime_image(
    project: Path,
    builder: BuilderOption,
    tag: str
) -> str:
    project_path = os.path.abspath(project)
    project_name = os.path.basename(project_path)
    image_name = f"{project_name}:{tag}"
    context = os.path.join(project_path, "plugins")
    containerfile = os.path.join(project_path, "plugins/Containerfile")
    os.system(f"{builder} build -f {containerfile} -t {image_name} {context}")
    return image_name

def export_container(builder: BuilderOption, container_name: str, dest: Path):
    os.makedirs(dest, exist_ok=True)
    tar_path = os.path.join(dest, "rootfs.tar")
    rootfs_dir = os.path.join(dest, "rootfs")
    os.system(f"{builder} export {container_name} > {tar_path}")
    os.makedirs(rootfs_dir, exist_ok=True)
    os.system(f"tar -xf {tar_path} --directory={rootfs_dir}")
    squashfs = os.path.join(dest, "rootfs.squashfs")
    if os.path.exists(squashfs):
        os.remove(squashfs)
    os.system(f"mksquashfs {rootfs_dir} {squashfs}")

@app.command()
def build(
    project: Path = typer.Argument(".", help="The name of your project"),
    builder: BuilderOption = typer.Option(BuilderOption.podman, help="Choose between docker and podman to build your runtime"),
    tag: str = typer.Option("latest", help="tag of your runtime tag")
):
    """Build a runtime created with the init command, using podman or docker"""
    project_path = os.path.abspath(project)
    image_name = build_runtime_image(project, builder, tag)
    os.makedirs(os.path.join(project_path, "build"), exist_ok=True)
    container_name = image_name.split(":")[0] + "_export"
    os.system(f"{builder} container create --name {container_name} {image_name}")
    export_container(builder, container_name, os.path.join(project_path, "build/release"))
    os.system(f"{builder} container rm {container_name}")

@app.command()
def test(
    project: Path = typer.Argument(".", help="The name of your project"),
    is_build: bool = typer.Option(False, "--build", help="If --build, build the runtime before testing. Else, finds runtime in project/build/"),
    builder: BuilderOption = typer.Option(BuilderOption.podman, help="Same as aleph runtime build --builder"),
    tag: str = typer.Option("latest", help="Same as aleph runtime build --tag")
):
    project_path = os.path.abspath(project)
    project_name = os.path.basename(project_path)
    image_name = f"{project_name}:{tag}"
    if is_build:
        build_runtime_image(project, builder, tag)
    container_name = project_name + "_test"
    os.system(f"{builder} run -it --name {container_name} {image_name} touch /root/sdk_test")
    os.system(f"{builder} cp plugins/test_data.py {container_name}:/root/test_data.py")
    os.system(f"{builder} commit {container_name} {project_name}:test")
    export_container(builder, container_name, os.path.join(project_path, "build/test"))

    firecracker_socket = "/tmp/firecracker.socket"
    firecracker_config_file = "vm_config.json"
    if os.path.exists(firecracker_socket):
        os.system(f"sudo rm {firecracker_socket}")
    os.system(f"sudo ./firecracker/firecracker --api-sock {firecracker_socket} --config-file {firecracker_config_file}")
