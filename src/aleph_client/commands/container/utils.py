
import os
import logging
from shutil import rmtree

from aleph_client.conf import Settings
from aleph_client.commands.container.save import save_tar

logger = logging.getLogger(__name__)


def create_container_volume(
    image: str,
    output: str,
    from_remote: bool,
    from_daemon: bool,
    optimize: bool,
    settings: Settings
) -> str:
    if from_remote:
        raise NotImplementedError()
        # echo(f"Downloading {image}")
        # registry = Registry()
        # tag = "latest"
        # if ":" in image:
        #     l = image.split(":")
        #     tag = l[-1]
        #     image = l[0]
        # print(tag)
        # image_object = registry.pull_image(image, tag)
        # manifest = registry.get_manifest_configuration(image, tag)
        # image_archive = os.path.abspath(f"{str(uuid4())}.tar")
        # image_object.write_filename(image_archive)
        # image = image_archive
        # print(manifest)
    elif from_daemon:
        output_from_daemon = f"{image}.tar"
        if os.system(f"docker image inspect {image} >/dev/null 2>&1"):
            raise Exception(f"Can't find image '{image}'")
        if os.system(f"docker save {image} > {output_from_daemon}") != 0:
            raise Exception("Error while saving docker image")
        image = output_from_daemon
    output = os.path.abspath(output)
    tmp_output = f"{output}.tmp"
    settings.DOCKER_SETTINGS.storage_driver.conf.optimize = optimize
    save_tar(image, tmp_output, settings=settings.DOCKER_SETTINGS)
    if not settings.CODE_USES_SQUASHFS:
        raise Exception("The command mksquashfs must be installed!")
    logger.debug("Creating squashfs archive...")
    os.system(
        f"mksquashfs {tmp_output} {output} -noappend"
    )
    rmtree(tmp_output)