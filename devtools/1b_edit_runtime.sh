#!/bin/sh
set -euf

apt install squashfs-tools -y

rootfs_dir=runtimes
runtime=63f07193e6ee9d207b7d1fcf8286f9aee34e6f12f101d2ec77c1229f92964696.squashfs
mount_dir=vm
mkdir -p ${mount_dir}/ro
mkdir -p ${mount_dir}/new

mount -o loop,ro -t squashfs ${rootfs_dir}/${runtime} ${mount_dir}/ro
cp -ar ${mount_dir}/ro ${mount_dir}/new
umount ${mount_dir}/ro

#mksquashfs ${mount_dir}/new new.squashfs -noappend -quiet
