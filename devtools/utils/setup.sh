#!/bin/bash
set -euf

# Install Debian Packages
apt-get install -y --no-install-recommends --no-install-suggests \
    python3-minimal \
    openssh-server \
    socat libsecp256k1-dev \
    python3-aiohttp python3-msgpack \
    python3-setuptools python3-venv \
    python3-pip python3-cytoolz python3-pydantic \
    iproute2 unzip \
    nodejs npm \
    build-essential python3-dev \
    python3-fastapi \
    docker.io \
    cgroupfs-mount \
    nftables \
    iputils-ping curl \
    locales

# Update locale settings to en_US UTF-8
echo "en_US.UTF-8 UTF-8" >/etc/locale.gen
locale-gen en_US.UTF-8

# Install Python packages
pip3 install --upgrade pip
mkdir -p /opt/aleph/libs
pip3 install --target /opt/aleph/libs aleph-sdk-python aleph-message fastapi

# Compile Python code to bytecode for faster execution
# -o2 is needed to compile with optimization level 2 which is what we launch init1.py ("python -OO")
# otherwise they are not used
python3 -m compileall -o 2 -f /usr/local/lib/python3.11
python3 -m compileall -o 2 -f /opt/aleph/libs

echo "PubkeyAuthentication yes" >>/etc/ssh/sshd_config
echo "PasswordAuthentication no" >>/etc/ssh/sshd_config
echo "ChallengeResponseAuthentication no" >>/etc/ssh/sshd_config
echo "PermitRootLogin yes" >>/etc/ssh/sshd_config

mkdir -p /overlay

# Set up a login terminal on the serial console (ttyS0):
ln -s agetty /etc/init.d/agetty.ttyS0
echo ttyS0 >/etc/securetty
