#!/bin/bash
set -eux
dd if=disk.img bs=512 skip=2023 count=1 2>/dev/null |xxd 
echo "done"
