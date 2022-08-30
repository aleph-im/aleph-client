import unittest
import os
import time
from typing import List
import filecmp
import subprocess
from shutil import rmtree
from save import save_tar
from conf import settings

TEST_DIR = os.path.abspath("test_data")
DOCKER_DATA = os.path.join(TEST_DIR, "docker")
IMAGE_NAME = "test-image"
TEST_DOCKER_DATA = os.path.join(TEST_DIR, "docker.emulate")
IMAGE_ARCHIVE = os.path.join(TEST_DIR, f"{IMAGE_NAME}.tar")

# TODO: setup for following test cases:
# - VFS optimization is turned on
# - tar-split is not used

def compare_folders_content(folder1: str, folder2: str):
    dcmp = filecmp.dircmp(folder1, folder2)
    def recursive_cmp(dcmp):
        diff = dcmp.left_only + dcmp.right_only + dcmp.diff_files
        for sub_dcmp in dcmp.subdirs.values():
            diff += recursive_cmp(sub_dcmp)

        return diff

    return recursive_cmp(dcmp)

docker_daemon: subprocess.Popen = None

class TestLoadImage(unittest.TestCase):

    @classmethod
    def setUpClass(cls) -> None:
        def cleanup_docker():
            os.system(f"rm -rf {DOCKER_DATA}")
            os.system("systemctl stop docker.service")
            cls.docker_daemon = subprocess.Popen(["dockerd", "--data-root", DOCKER_DATA], stderr=subprocess.DEVNULL)
            time.sleep(3)

        def build_test_image() -> bool:
            if os.path.exists(IMAGE_ARCHIVE):
                return True
            return (
                os.system(f"docker build -t {IMAGE_NAME} {TEST_DIR}") == 0
                and os.system(f"docker save {IMAGE_NAME} > {IMAGE_ARCHIVE}") == 0
            )

        def load_image():
            os.system(f"docker load -i {IMAGE_ARCHIVE}")

        if not build_test_image():
            raise Exception("Could not properly build imaqge")
        cleanup_docker()
        load_image()
        settings.storage_driver.conf.optimize = False
        save_tar(IMAGE_ARCHIVE, TEST_DOCKER_DATA, settings)

    @classmethod
    def tearDownClass(cls) -> None:
        rmtree(TEST_DOCKER_DATA)
        rmtree(DOCKER_DATA)
        if cls.docker_daemon is not None:
            print("KILLING DOCKERD")
            cls.docker_daemon.kill()
            time.sleep(3)
        os.system("systemctl restart docker.socket")
        time.sleep(3)
        os.system("systemctl restart docker.service")

    def test_dir_creation(self) -> None:
        self.assertTrue(os.path.isdir(f"{TEST_DOCKER_DATA}"))

    def folder_cmp(self, expected_path: str, result_path: str) -> List[bool]:
        res = []
        expected_result = os.listdir(expected_path)
        result = os.listdir(result_path)
        self.assertEqual(len(expected_result), len(result))
        for folder in expected_result:
            res.append(folder in result)
        return res

    def permissions_cmp(self, expected_path, actual_path):
        res = []
        expected_files = os.listdir(expected_path)
        for f in expected_files:
            expected_mode = os.stat(os.path.join(expected_path, f)).st_mode
            actual_mode = os.stat(os.path.join(actual_path, f)).st_mode
            if expected_mode != actual_mode:
                print(os.path.join(expected_path, f), oct(expected_mode), oct(actual_mode))
            res.append(expected_mode == actual_mode)
        return res

    def test_docker_dir_same(self) -> None:
        for res in self.folder_cmp(DOCKER_DATA, TEST_DOCKER_DATA):
            self.assertTrue(res)
        for res in self.permissions_cmp(DOCKER_DATA, TEST_DOCKER_DATA):
            self.assertTrue(res)

    def test_docker_image_dir_same(self) -> None:
        for res in self.folder_cmp(
            os.path.join(DOCKER_DATA, "image"),
            os.path.join(TEST_DOCKER_DATA, "image")
        ):
            self.assertTrue(res)
        for res in self.permissions_cmp(
            os.path.join(DOCKER_DATA, "image"),
            os.path.join(TEST_DOCKER_DATA, "image")
        ):
            self.assertTrue(res)

    def test_docker_image_vfs_dir_same(self) -> None:
        for res in self.folder_cmp(
            os.path.join(DOCKER_DATA, "image", "vfs"),
            os.path.join(TEST_DOCKER_DATA, "image", "vfs")
        ):
            self.assertTrue(res)
        for res in self.permissions_cmp(
            os.path.join(DOCKER_DATA, "image", "vfs"),
            os.path.join(TEST_DOCKER_DATA, "image", "vfs")
        ):
            self.assertTrue(res)

    def test_compare_repositories_json(self) -> None:
        path = os.path.join("image", "vfs", "repositories.json")
        expected_result_path = os.path.join(DOCKER_DATA, path)
        result_path = os.path.join(TEST_DOCKER_DATA, path)
        self.assertTrue(filecmp.cmp(expected_result_path, result_path))

    def test_imagedb_same(self) -> None:
        for res in self.folder_cmp(
            os.path.join(DOCKER_DATA, "image", "vfs", "imagedb"),
            os.path.join(TEST_DOCKER_DATA, "image", "vfs", "imagedb")
        ):
            self.assertTrue(res)
        for res in self.permissions_cmp(
            os.path.join(DOCKER_DATA, "image", "vfs", "imagedb"),
            os.path.join(TEST_DOCKER_DATA, "image", "vfs", "imagedb")
        ):
            self.assertTrue(res)

    def test_imagedb_content_same(self) -> None:
        path = os.path.join("image", "vfs", "imagedb", "content", "sha256")
        for res in self.folder_cmp(
            os.path.join(DOCKER_DATA, path),
            os.path.join(TEST_DOCKER_DATA, path)
        ):
            self.assertTrue(res)

        for res in self.permissions_cmp(
            os.path.join(DOCKER_DATA, path),
            os.path.join(TEST_DOCKER_DATA, path)
        ):
            self.assertTrue(res)

    def test_imagedb_meta_same(self) -> None:
        path = os.path.join("image", "vfs", "imagedb", "metadata", "sha256")
        for res in self.folder_cmp(
            os.path.join(DOCKER_DATA, path),
            os.path.join(TEST_DOCKER_DATA, path)
        ):
            self.assertTrue(res)
        for res in self.permissions_cmp(
            os.path.join(DOCKER_DATA, path),
            os.path.join(TEST_DOCKER_DATA, path)
        ):
            self.assertTrue(res)

    def test_compare_imagedb_files(self) -> None:
        path = os.path.join("image", "vfs", "imagedb", "content", "sha256")
        expected_result_dir = os.path.join(DOCKER_DATA, path)
        result_dir = os.path.join(TEST_DOCKER_DATA, path)
        for f in os.listdir(expected_result_dir):
            result_file = os.path.join(result_dir, f)
            expected_result_file = os.path.join(expected_result_dir, f)
            self.assertTrue(filecmp.cmp(expected_result_file, result_file))

    def test_compare_layerdb_same(self) -> None:
        path = os.path.join("image", "vfs", "layerdb", "sha256")
        for res in self.folder_cmp(
            os.path.join(DOCKER_DATA, path),
            os.path.join(TEST_DOCKER_DATA, path)
        ):
            self.assertTrue(res)
        for res in self.permissions_cmp(
            os.path.join(DOCKER_DATA, path),
            os.path.join(TEST_DOCKER_DATA, path)
        ):
            self.assertTrue(res)

    def test_compare_layerdb_files(self) -> None:
        path = os.path.join("image", "vfs", "layerdb", "sha256")
        for folder in os.listdir(os.path.join(DOCKER_DATA, path)):
            for f in os.listdir(os.path.join(DOCKER_DATA, path, folder)):
                if f == "size": # not ready yet
                    continue
                result_file = os.path.join(TEST_DOCKER_DATA, path, folder, f)
                expected_result_file = os.path.join(DOCKER_DATA, path, folder, f)
                res = filecmp.cmp(result_file, expected_result_file)
                if f == "cache-id": # uuid should not be identical
                    self.assertFalse(res)
                else:
                    self.assertTrue(res)

    def test_compare_layers(self) -> None:
        path = os.path.join("image", "vfs", "layerdb", "sha256")
        for folder in os.listdir(os.path.join(DOCKER_DATA, path)):
            with open(os.path.join(DOCKER_DATA, path, folder, "cache-id"), "r") as f:
                cache_id1 = f.read()
            with open(os.path.join(TEST_DOCKER_DATA, path, folder, "cache-id"), "r") as f:
                cache_id2 = f.read()

            res = compare_folders_content(
                os.path.join(DOCKER_DATA, "vfs", "dir", cache_id1),
                os.path.join(TEST_DOCKER_DATA, "vfs", "dir", cache_id2),
            )
            self.assertEqual(len(res), 0)

if __name__ == '__main__':
    unittest.main()