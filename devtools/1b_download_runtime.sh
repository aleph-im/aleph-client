#!/bin/sh
set -euf

default_runtime=63f07193e6ee9d207b7d1fcf8286f9aee34e6f12f101d2ec77c1229f92964696
get_message_url=https://api1.aleph.im/api/v0/messages/
ipfs_gateway=https://ipfs.aleph.im/ipfs/
rootfs_dir=runtimes
mkdir -p $rootfs_dir

# Ask for runtime item hash
read -p "Enter a runtime item hash (leave blank for default): " runtime
if [ -z "${runtime}" ]; then
    runtime=$default_runtime
    echo "Using default runtime: ${runtime}"
else
    echo "Using provided runtime: ${runtime}"
fi

# Get item hash message
message=$(curl -s -X GET "$get_message_url$runtime")
ipfs_cid=$(echo "$message" | jq -r '.message.content.item_hash')
#echo "IPFS CID: $ipfs_cid"

# Get runtime file
runtime_file="${runtime}.squashfs"
download_url="$ipfs_gateway$ipfs_cid"
if [ ! -f "${rootfs_dir}/${runtime_file}" ]; then
    echo "Downloading ${runtime_file}..."
    curl -L $download_url -o ${rootfs_dir}/${runtime_file}
    echo "Download complete."
else
    echo "${runtime_file} is already available."
fi
