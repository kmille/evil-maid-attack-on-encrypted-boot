#!/bin/bash
set -eux

DEPLOY_IMG=../working-dir/core/patched-core.img
#DEPLOY_IMG=../working-dir/core/core-org.img

# backup mbr
dd if=disk.img of=mbr.dd bs=512 count=1

# clean everything until first partition
dd if=/dev/zero of=disk.img bs=512 count=2048 conv=notrunc

# restore MBR
dd if=mbr.dd of=disk.img conv=notrunc

# restore patched core.img
dd if=$DEPLOY_IMG of=disk.img bs=512 seek=1 conv=notrunc
sync

echo "done"
