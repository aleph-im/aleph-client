import tarfile
from typing import Dict
from .image import Image
import os
import json
from uuid import uuid4
import tarfile
import subprocess
from shutil import rmtree
import tempfile
import gzip
from .docker_conf import DockerSettings, StorageDriverEnum

class IStorageDriver:
    def create_file_architecture(self):
        """
        Reproduce the /var/lib/docker needed files in output_dir based on an image object.
        """
        pass


class AStorageDriver(IStorageDriver):

    image: Image
    output_dir: str
    layer_ids_dict: Dict[str, str]
    driver_dir: str

    def __init__(self, image: Image, output_dir: str, driver_dir: str):
        self.image = image
        self.output_dir = output_dir
        self.layer_ids_dict = {}
        self.driver_dir = driver_dir

    def create_file_architecture(self):
        path = os.path.join(self.output_dir, "image", self.driver_dir)
        os.makedirs(path, 0o700)
        self.create_distribution(path)
        self.create_repositories_json(path)
        self.create_imagedb(path)
        self.create_layerdb(self.output_dir)
        return

    def create_repositories_json(self, output_dir: str):
        """
        Reproduce /var/lib/docker/image/{storage_driver}/repositories.json
        in output_dir based on an image object.
        """
        raise NotImplementedError(f"You must implement this method")

    def create_imagedb(self, output_dir: str):
        """
        Reproduce /var/lib/docker/image/{storage_driver}/imagedb
        in output_dir based on an image object.
        """
        raise NotImplementedError(f"You must implement this method")

    def create_layerdb(self, output_dir: str):
        """
        Reproduce /var/lib/docker/image/{storage_driver}/layerdb
        in output_dir based on an image object after extracting the layers
        to {output_dir}/{storage_driver}.
        """
        raise NotImplementedError(f"You must implement this method")

    def create_distribution(self, output_dir: str):
        """
        Reproduce /var/lib/docker/image/{storage_driver}/disctibution
        in output_dir based on an image object.
        """
        raise NotImplementedError(f"You must implement this method")



# Since aleph vms can be running with an unknown host configuration,
# storage drivers can be different from a machine to an other.
# Although not the most performant one, VFS is the most compatible
# storage driver, hence the use of it.
# Future use of an other storage driver such as Overlay2 might become
# available as compatibility checks are done on vms
class Vfs(AStorageDriver):

    def __init__(self, image: Image, output_dir: str, settings: DockerSettings):
        super().__init__(image, output_dir, "vfs")
        self.optimize = settings.storage_driver.conf.optimize
        self.use_tarsplit = settings.storage_driver.conf.use_tarsplit

    def create_distribution(self, output_dir: str):
        os.makedirs(os.path.join(output_dir, "distribution"), 0o700)

    def create_repositories_json(self, output_dir: str):
        repositories = {}
        for name, tags in self.image.repositories.items():
            repositories[name] = {}
            for tag in tags.keys():
                repositories[name][f"{name}:{tag}"] = f"sha256:{self.image.image_digest}"
        repositories = {"Repositories": repositories}
        path = os.path.join(output_dir, "repositories.json")
        with open(path, "w") as f:
            f.write(json.dumps(repositories, separators=(',', ':')))
        os.chmod(path, 0o0600)

    def create_imagedb(self, output_dir: str):
        os.makedirs(os.path.join(output_dir, "imagedb"), 0o700)
        os.makedirs(os.path.join(output_dir, "imagedb", "content"), 0o700)
        os.makedirs(os.path.join(output_dir, "imagedb", "metadata"), 0o700)
        os.makedirs(os.path.join(output_dir, "imagedb", "content", "sha256"), 0o700)
        os.makedirs(os.path.join(output_dir, "imagedb", "metadata", "sha256"), 0o700)
        # os.makedirs(os.path.join(metadata, self.image.image_digest))
        content = os.path.join(output_dir, "imagedb", "content", "sha256")
        path = os.path.join(content, self.image.image_digest)
        with open(path, "w") as f:
            f.write(json.dumps(self.image.config, separators=(',', ':'))) # This file must be dumped compactly in order to keep the correct sha256 digest
        os.chmod(path, 0o0600)
        # with open(os.path.join(metadata, self.image.image_digest, "parent"), "w") as f:
        #     f.write(self.image.config['config']['Image'])
        return

    def create_layerdb(self, output_dir: str):
        assert (
            len(self.image.chain_ids) == len(self.image.diff_ids)
            and len(self.image.diff_ids) == len(self.image.layers_ids)
        )
        layers_dir = os.path.join(output_dir, "vfs", "dir")
        layerdb_path = os.path.join(output_dir, "image", "vfs", "layerdb")
        os.makedirs(layerdb_path, 0o700)
        os.makedirs(os.path.join(layerdb_path, "mounts"), 0o700)
        os.makedirs(os.path.join(layerdb_path, "tmp"), 0o700)
        layerdb_path = os.path.join(layerdb_path, "sha256")
        os.makedirs(layerdb_path, 0o700)

        def save_layer_metadata(path: str, diff: str, cacheid: str, size: int, previous_chain_id: str or None):
            dest = os.path.join(path, "diff")
            with open(dest, "w") as fd:
                fd.write(diff)
            os.chmod(dest, 0o600)
            dest = os.path.join(path, "cache-id")
            with open(dest, "w") as fd:
                fd.write(cacheid)
            os.chmod(dest, 0o600)
            dest = os.path.join(path, "size")
            with open(dest, "w") as fd:
                fd.write(str(size))
            os.chmod(dest, 0o600)
            dest = os.path.join(path, "parent")
            if previous_chain_id is not None:
                with open(dest, "w") as fd:
                    fd.write(previous_chain_id)
                os.chmod(dest, 0o600)


        def copy_layer(src: str, dest: str) -> None:
            for folder in os.listdir(src):
                subprocess.check_output(["cp", "-r", os.path.join(src, folder), dest])

        def compute_layer_size(tar_data_json_path: str) -> int:
            size = 0
            with gzip.open(tar_data_json_path, "r") as archive:
                data = json.loads(
                    "["
                    + archive.read().decode().replace("}\n{", "},\n{")
                    + "]"
                ) # fixes poor formatting from tar-split
            for elem in data:
                if "size" in elem.keys():
                    size =+ elem["size"]
            return size

        def extract_layer(path: str, archive_path: str, layerdb_subdir: str) -> int:
            cwd = os.getcwd()
            tmp_dir = tempfile.mkdtemp()
            os.chdir(tmp_dir)
            tar_src = os.path.join(tmp_dir, "layer.tar")
            tar_dest = os.path.join(layer_id, "layer.tar")
            with tarfile.open(archive_path, "r") as tar:
                tar.extract(tar_dest)
            os.rename(tar_dest, tar_src)
            os.rmdir(layer_id)
            os.chdir(path)

            # tar-split is used by docker to keep some archive metadata
            # in order to compress the layer back with the exact same digest
            # Mandatory if one plans to export a docker image to a tar file
            # https://github.com/vbatts/tar-split
            if self.use_tarsplit:
                tar_data_json = os.path.join(layerdb_subdir, "tar-split.json.gz")
                os.system(f"tar-split disasm --output {tar_data_json} {tar_src} | tar -C . -x")
                size = compute_layer_size(tar_data_json) # Differs from expected. Only messes with docker image size listing
                os.remove(tar_src)

            # Also works, but won't be able to export images
            else:
                with tarfile.open(tar_src, "r") as tar:
                    os.remove(tar_src)
                    tar.extractall()
                size=0
            os.rmdir(tmp_dir)
            os.chdir(cwd)
            return size

        previous_cache_id = None
        for i in range(0, len(self.image.chain_ids)):
            chain_id = self.image.chain_ids[i]
            layerdb_subdir = os.path.join(layerdb_path, chain_id.replace("sha256:", ""))
            os.makedirs(layerdb_subdir, 0o700)
            cache_id = (str(uuid4()) + str(uuid4())).replace("-", "")

            layer_id = self.image.layers_ids[i]
            current_layer_path = os.path.join(layers_dir, cache_id)
            os.makedirs(current_layer_path, 0o700)


            # Merge layers
            # The last layer contains changes from all the previous ones
            if previous_cache_id:
                previous_layer_path = os.path.join(layers_dir, previous_cache_id)
                copy_layer(previous_layer_path, current_layer_path)
                if (self.optimize):
                    rmtree(previous_layer_path)
            previous_cache_id = cache_id
            size = extract_layer(current_layer_path, self.image.archive_path, layerdb_subdir)
            save_layer_metadata(
                path=layerdb_subdir,
                diff=self.image.diff_ids[i],
                cacheid=cache_id,
                size=size,
                previous_chain_id=self.image.chain_ids[i - 1]
                if i > 0
                else None
            )


def create_storage_driver(
    image: Image,
    output_dir: str,
    settings: DockerSettings
) -> IStorageDriver:
    if settings.storage_driver.kind == StorageDriverEnum.VFS:
        return Vfs(image, output_dir, settings)
    raise NotImplementedError("Only vfs supported now")