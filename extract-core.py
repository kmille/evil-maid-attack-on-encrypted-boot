#!/usr/bin/env python3
from utils import clean_working_directory
import struct

clean_working_directory()

disk = "test-vm/disk.img"
# disk_head is just a backup file we work with to not destroy the VM
disk_head = "working-dir/disk_head.dd"
offset_core_img = 512
size_diskboot_img = 512
core_extracted = "working-dir/core/core-extracted.img"


def main():
    print(f"Reading from disk image {disk}")
    with open(disk, "rb") as f:
        with open(disk_head, "wb") as fout:
            fout.write(f.read(2048 * 512))

    with open(disk_head, "rb") as f:
        # 0x1f4 = 500 (at the end of the sector)
        # check parse_diskboot_img for more details
        f.seek(offset_core_img + 0x1f4 + 8)
        print("kmille offset =", hex(offset_core_img + 0x1f4))
        size_in_sectors = struct.unpack("<H", f.read(2))[0]

    with open(disk_head, "rb") as f:
        print(f"core.img starts at sector 1. Seeking {offset_core_img} bytes")
        f.seek(offset_core_img)
        with open(core_extracted, "wb") as fout:
            # TODO: is this wrong?
            size_core_img = size_diskboot_img + 512 * size_in_sectors
            print(f"Size of core.img in sectors: {hex(size_in_sectors)}")
            fout.write(f.read(size_core_img))
    print(f"Dumped extraced core.img to {core_extracted}")


if __name__ == '__main__':
    main()
