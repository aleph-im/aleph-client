import sys
from aleph_client.commands.container.image import Image
from aleph_client.commands.container.storage_drivers import create_storage_driver
import os
from shutil import rmtree
from aleph_client.commands.container.docker_conf import docker_settings, DockerSettings

dirs = {
    "vfs": 0o710,
    "image": 0o700,
    "plugins": 0o700,
    "swarm": 0o700,
    "runtimes": 0o700,
    "network": 0o750,
    "trust": 0o700,
    "volumes": 0o701,
    "buildkit": 0o711,
    "containers": 0o710,
    "tmp": 0o700,
}


def populate_dir(output_path: str):
    print("populating")
    path = os.path.abspath(output_path)
    if os.path.exists(output_path) and os.path.isdir(output_path):
        try:
            rmtree(output_path)
        except:
            raise ""  # TODO: handle error
        os.makedirs(output_path, 0o710)
    for d, mode in dirs.items():
        os.makedirs(os.path.join(path, d), mode)


def save_tar(archive_path: str, output_path: str, settings: DockerSettings):
    archive_path = os.path.abspath(archive_path)
    output_path = os.path.abspath(output_path)
    image = Image(archive_path)
    if settings.populate:
        populate_dir(output_path)
    driver = create_storage_driver(image, output_path, settings)
    driver.create_file_architecture()


if __name__ == "__main__":
    save_tar(sys.argv[1], sys.argv[2], docker_settings)
