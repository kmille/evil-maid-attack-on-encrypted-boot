#!/usr/bin/env python
import argparse
import struct
from utils import find_image_in_blob, cmd, parse_grub_modules, parse_diskboot_img, clean_working_directory
from constants import MODULES_DECOMPRESSED, MODULES_COMPRESSED, KERNEL, SECTOR_SIZE


def dump_kernel(kernel_size: int) -> None:
    with open(MODULES_DECOMPRESSED, "rb") as f:
        kernel = f.read(kernel_size)
    with open(KERNEL, "wb") as f:
        f.write(kernel)
    print(f"Dumped kernel to {KERNEL}")


def decompress_modules(core_img: str, offset: int) -> None:
    lzma_data = b""
    with open(core_img, "rb") as f:
        f.seek(offset)
        while True:
            chunk = f.read()
            if not chunk:
                break
            lzma_data += chunk
    with open(MODULES_COMPRESSED, "wb") as f:
        f.write(lzma_data)
    print(f"Extracted compressed blob at offset {hex(offset)} to '{MODULES_COMPRESSED}'")
    # TODO: do this with python
    cmd(f"xzcat --lzma1 --format=raw < {MODULES_COMPRESSED} > {MODULES_DECOMPRESSED}")
    print(f"Decompressed blob to '{MODULES_DECOMPRESSED}'\n")


def parse_decompress_img(core_img: str, offset: int) -> int:
    # offset: sector in which lzma_decompress.img begins
    print(f"Parsing lzma_decompress.img in {core_img}")
    """
    include/grub/offsets.h
        /* The offset of GRUB_COMPRESSED_SIZE.  */
        #define GRUB_DECOMPRESSOR_I386_PC_COMPRESSED_SIZE   0x08

        /* The offset of GRUB_COMPRESSED_SIZE.  */
        #define GRUB_DECOMPRESSOR_I386_PC_UNCOMPRESSED_SIZE 0x0c
    """
    with open(core_img, "rb") as f:
        f.seek(offset+0x8)
        # TODO: assert these file sizes with modules-compressed.img and modules-decompressed.img
        decompressor_compressed_size = struct.unpack("<I", f.read(4))[0]
        decompressor_uncompressed_size = struct.unpack("<I", f.read(4))[0]
    print(f"lzma_decompress.img: decompressor_compressed_size={hex(decompressor_compressed_size)} decompressor_uncompressed_size={hex(decompressor_uncompressed_size)}\n")

    # TODO: find a better way to find the size of the lzma_decompress.img
    _, size = find_image_in_blob(core_img, "lzma_decompress.img", 7)
    return size


def parse_grub_module_info32() -> int:
    # decompressed_blob: kernel.img | grub_module_info32 (3* 4 bytes) | modules
    """ in include/grub/kernel.h
        #define GRUB_MODULE_MAGIC 0x676d696d

        struct grub_module_info32
        {
          /* Magic number so we know we have modules present.  */
          grub_uint32_t magic;
          /* The offset of the modules.  */
          grub_uint32_t offset;
          /* The size of all modules plus this header.  */
          grub_uint32_t size;
        };

    """
    with open(MODULES_DECOMPRESSED, "rb") as f:
        f.seek(0x13)
        kernel_size = struct.unpack("<i", f.read(4))[0]
        print(f"Parsed kernel_size ({hex(kernel_size)})")
        # grub_module_info32 comes after the kernel
        module_info_offset = kernel_size
        print(f"Parsing grub_module_info32 structure at offset {hex(module_info_offset)}")
        f.seek(module_info_offset)
        magic = struct.unpack("<i", f.read(4))[0]
        assert magic == 0x676d696d
        # offset is 12 because the size of grub_module_info32 is always 3*4 bytes
        offset = struct.unpack("<i", f.read(4))[0]
        assert offset == 3*4
        total_module_size = struct.unpack("<i", f.read(4))[0]
    print(f"grub_module_info32: magic={hex(magic)} offset={hex(offset)} total_module_size={hex(total_module_size)} ")
    dump_kernel(kernel_size)
    print()
    return kernel_size + offset


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("core", help="core image you want to analyze")
    args = parser.parse_args()

    print(f"Let's analyse {args.core} \\o/")
    clean_working_directory()
    find_image_in_blob(args.core, "diskboot.img", 1)
    lzma_code_sector_offset, _ = parse_diskboot_img(args.core)
    lzma_code_size = parse_decompress_img(args.core, lzma_code_sector_offset * SECTOR_SIZE)
    offset_compressed_blob = lzma_code_sector_offset * SECTOR_SIZE + lzma_code_size
    print(f"Decompressed data starts at offset {hex(offset_compressed_blob)}")
    decompress_modules(args.core, offset_compressed_blob)
    modules_offset = parse_grub_module_info32()
    parse_grub_modules(modules_offset)


if __name__ == '__main__':
    main()
