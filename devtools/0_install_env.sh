#!/bin/sh
set -euf

arch=$(uname -m)
image_bucket_url="https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/$arch"
bin_dir=bin
firecracker=firecracker
kernel=vmlinux.bin
mkdir -p ${bin_dir}

# Check architecture
if [ ${arch} = "x86_64" ]; then
    kernel_url="${image_bucket_url}/kernels/vmlinux.bin"
elif [ ${arch} = "aarch64" ]; then
    kernel_url="${image_bucket_url}/kernels/vmlinux.bin"
else
    echo "Cannot run firecracker on $arch architecture."
    exit 1
fi

# Dependencies
apt update -y
apt upgrade -y
apt install squashfs-tools debootstrap -y

# Get the Firecracker binary
if [ ! -f ${bin_dir}/${firecracker} ]; then
    echo "Installing Firecracker..."
    release_url="https://github.com/firecracker-microvm/firecracker/releases"
    latest=$(basename $(curl -fsSLI -o /dev/null -w %{url_effective} ${release_url}/latest))
    arch=$(uname -m)
    if curl -L ${release_url}/download/${latest}/firecracker-${latest}-${arch}.tgz | tar -xz; then
        bin_folder="release-${latest}-$(uname -m)"
        mv "${bin_folder}/firecracker-${latest}-$(uname -m)" ${bin_dir}/${firecracker}
        rm -r "${bin_folder}"
        echo "Firecracker installation complete."
    else
        echo "Failed to install Firecracker. Please check your network connection and try again."
        exit 1
    fi
else
    echo "Firecracker is already installed."
fi

# Get the vmlinux.bin
if [ ! -f ${bin_dir}/${kernel} ]; then
    echo "Installing kernel..."
    if curl -L -o ${bin_dir}/${kernel} $kernel_url; then
        echo "${kernel} installation complete."
    else
        echo "Failed to install ${kernel}. Please check your network connection and try again."
        exit 1
    fi
else
    echo "${kernel} is already installed."
fi

# Docker installation
if docker --version >/dev/null 2>&1; then
    echo "Docker is already installed."
else
    apt install docker.io -y
fi
# Docker without sudo
groupadd -f docker
usermod -aG docker $(whoami)
docker context use default

echo "Environment setup complete."
