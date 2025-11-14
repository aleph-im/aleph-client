#!/bin/sh
set -euf

if docker --version >/dev/null 2>&1; then
    echo "Docker is already installed."
else
    apt install docker.io -y
fi

if [ $# -ne 1 ]; then
    echo "Error: Please provide the application directory as an argument."
    echo "Usage: $0 <app_dir>"
    exit 1
fi

app_dir=programs/$1
deps_file="${app_dir}/requirements.txt"
output_file="built_${app_dir}/packages.squashfs"

echo "Packing dependencies for ${app_dir} into ${output_file} using ${deps_file}"

if [ ! -d "$app_dir" ]; then
    echo "Error: The application directory '$app_dir' does not exist."
    exit 1
fi
if [ ! -f "$deps_file" ]; then
    echo "Error: The requirements file '$deps_file' does not exist."
    exit 1
fi

rm -f "$output_file"
touch "$output_file"

docker run --rm -t --platform linux/amd64 \
    -v "$(pwd)/${deps_file}:/opt/requirements.txt" \
    -v "$(pwd)/${output_file}:/opt/packages.squashfs" \
    debian:bookworm /bin/bash \
    -c "apt-get update -y;
apt-get install python3-pip squashfs-tools -y;
python3 -V;
pip install -t /opt/packages -r /opt/requirements.txt;
mksquashfs /opt/packages /opt/packages.squashfs -noappend -quiet"

echo "Dependencies packed into ${output_file} successfully."
