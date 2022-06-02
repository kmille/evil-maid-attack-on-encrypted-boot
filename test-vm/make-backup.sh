#!/bin/bash
set -eu
dd of=backup.dd if=disk.img bs=512 count=2048

echo "done"

