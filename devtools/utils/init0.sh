#!/bin/sh
set -euf

# Mounting userful system filesystems
mount -t proc proc /proc -o nosuid,noexec,nodev
mkdir -p /dev/pts
mkdir -p /dev/shm
mount -t sysfs sys /sys -o nosuid,noexec,nodev
mount -t tmpfs run /run -o mode=0755,nosuid,nodev
mount -t devpts devpts /dev/pts -o mode=0620,gid=5,nosuid,noexec
mount -t tmpfs shm /dev/shm -omode=1777,nosuid,nodev

exec /root/init1.py
