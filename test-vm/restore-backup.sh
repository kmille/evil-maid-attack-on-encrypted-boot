#!/bin/bash
set -eu
dd if=backup.dd of=disk.img conv=notrunc

echo "done"
