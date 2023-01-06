
from os import rename
from platform import uname
from .utils import (
    download_file,
    download_tmp_file,
    get_repo_latest_version,
    extract_archive_to_dir
)

FIRECRACKER_GITHUB_REPO="https://github.com/firecracker-microvm/firecracker"
IMAGE_BUCKET_URL="https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide"
KERNEL_PATH=f"kernels/vmlinux.bin"
ROOTFS_PATH=f"rootfs/bionic.rootfs.ext4"


def check_arch_compatibility(arch: str) -> bool:
    if arch not in ["x86_64", "aarch64"]:
        print(f"Cannot run firecracker on {arch} architecture!")
        exit(1)

def download_firecracker_bin(arch: str, version: str, dest: str):
    url = f"{FIRECRACKER_GITHUB_REPO}/releases/download/{version}/firecracker-{version}-{arch}.tgz"
    output_dir = f"{dest}/release-{version}-{arch}"
    extract_archive_to_dir(download_tmp_file(url), f"{dest}")
    firecracker_bin = f"{output_dir}/firecracker-{version}-{arch}"
    rename(firecracker_bin, f"{output_dir}/firecracker")
    rename(output_dir, f"{dest}/firecracker")

def download_firecracker(path: str):
    latest = get_repo_latest_version(FIRECRACKER_GITHUB_REPO)
    arch = uname().machine
    check_arch_compatibility(arch)
    print("Downloading firecracker...")
    download_firecracker_bin(arch, latest, path)
    kernel_url = f"{IMAGE_BUCKET_URL}/{arch}/{KERNEL_PATH}"
    print("Downloading kernel...")
    download_file(kernel_url, f"{path}/vmlinux.bin")

if __name__ == "__main__":
    download_firecracker("./")
