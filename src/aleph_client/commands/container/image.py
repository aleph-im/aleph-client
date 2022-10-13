from typing import List, Dict, Union, NewType
import os
import tarfile
from tarfile import TarFile
import json
from hashlib import sha256

Command = NewType('Command', Dict[str, str])
ConfigValue = NewType('ConfigValue', Union[str, bool, None, Command])

class Image:
    config: Dict[str, ConfigValue]
    image_digest: str
    repositories: Dict[str, object]
    archive_path: str

    # Parent at index 0, child at len(list) - 1
    layers_ids: List[str]
    chain_ids: List[str]
    diff_ids: List[str]

    def to_dict(self):
        return self.__dict__

    def get_tar_filenames(tar: TarFile) -> List[str]:
        files = tar.getmembers()
        filenames = []
        for file in files:
            filenames.append(file.get_info()["name"])
        return filenames

    def __load_metadata(self, tar: TarFile, file: str) -> Dict[str, str]:
        return json.load(tar.extractfile(file))

    def __init__(self, path: str):
        if not os.path.exists(path):
            raise ValueError("File does not exist")
        if not tarfile.is_tarfile(path):
            raise ValueError("Invalid tar archive")
        self.archive_path = path
        with tarfile.open(self.archive_path, "r") as tar:
            manifest = self.__load_metadata(tar, "manifest.json")
            self.repositories = self.__load_metadata(tar, "repositories")
            self.image_digest = manifest[0]["Config"].split(".")[0]
            self.config = self.__load_metadata(tar, f"{self.image_digest}.json")
        self.layers_ids = list(map(
            lambda name: name.split('/')[0],
            manifest[0]["Layers"]
        )) # Only keep the Layer id, not the file path
        self.diff_ids = self.config["rootfs"]["diff_ids"]
        self.chain_ids = self.__compute_chain_ids()

    def __compute_chain_ids(self) -> List[str]:
        chain_ids = []
        # diff_ids are stored sequentially, from parent to child.
        # If the file has been tempered, this method cannot work.

        # I used recursion because it was simpler to execute, not because it's better
        # cause it's not. TODO: use iteration
        def recursive_compute_chain_id(index: int) -> str:
            # ChainID(A) = DiffID(A)
            # ChainID(A|B) = Digest(ChainID(A) + " " + DiffID(B))
            # ChainID(A|B|C) = Digest(ChainID(A|B) + " " + DiffID(C))
            # https://github.com/opencontainers/image-spec/blob/main/config.md
            if index == 0:
                diff_id = self.diff_ids[index]
                chain_ids.append(diff_id)
                return diff_id
            chain_id = "sha256:" + sha256(
                recursive_compute_chain_id(index - 1).encode()
                + " ".encode()
                + self.diff_ids[index].encode()
            ).hexdigest()
            chain_ids.append(chain_id)
            return chain_id



        # TODO: test this iterative version
        iterative_chain_ids = []
        def iterative_compute_chain_id(index: int) -> str:
            diff_id = self.diff_ids[0]
            iterative_chain_ids.append(diff_id)
            i = 1
            while i < index:
                chain_id = "sha256:" + sha256(
                iterative_chain_ids[i - 1].encode()
                + " ".encode()
                + self.diff_ids[i].encode()
            ).hexdigest()
            iterative_chain_ids.append(chain_id)
            return

        recursive_compute_chain_id(len(self.layers_ids) - 1)

        return chain_ids
