#!/bin/bash
set -eu
dd if=/dev/zero of=disk.img bs=512 skip=2023 seek=2023 count=1 conv=notrunc
echo "done"
