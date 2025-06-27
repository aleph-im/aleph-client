#!/bin/sh
set -euf

runtime=$1

# Utils
setup=utils/setup.sh
inittab=utils/inittab
init=utils/init0.sh
init_py=utils/init1.py
loading_html=utils/loading.html

# Temp Files
dest=/mnt/rootfs

# Target
rootfs_dir=runtimes
target=$rootfs_dir/$runtime.squashfs
mkdir -p $rootfs_dir

# Cleanup previous run
rm -rf $target
rm -rf $dest
mkdir $dest

echo "Downloading Debian Bullseye minimal"
debootstrap --variant=minbase bullseye $dest http://deb.debian.org/debian/

echo "Run setup script"
chmod +x $setup
cp $setup $dest/setup.sh
chroot $dest /bin/sh -c "./setup.sh && rm -f setup.sh"

# Reduce size
rm -fr $dest/root/.cache
rm -fr $dest/var/cache
mkdir -p $dest/var/cache/apt/archives/partial
rm -fr $dest/usr/share/doc
rm -fr $dest/usr/share/man
rm -fr $dest/var/lib/apt/lists

echo "Install init scripts"
cp $inittab $dest/etc/inittab
chmod +x $init
chmod +x $init_py
cp $init $dest/sbin/init
cp $init_py $dest/root/init1.py
cp $loading_html $dest/root/loading.html

echo "Creating squashfs image"
mksquashfs $dest $target -noappend -quiet
rm -rf $dest
echo "Done"
