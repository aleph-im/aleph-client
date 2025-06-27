#!/bin/sh
set -euf

in=programs/$1
out_dir=built_programs/$1
mkdir -p $out_dir
out=$out_dir/program.squashfs
rm -f $out
mksquashfs $in $out -noappend -quiet
