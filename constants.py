import os.path

MODULE_DIR = "modules"
WORKING_DIR = "working-dir"
#CORE = os.path.join(WORKING_DIR, "core/core-debian.img")
#CORE = os.path.join(WORKING_DIR, "core/core-debian-with-disk.img")
PATCHED_CORE = os.path.join(WORKING_DIR, "core", "patched-core.img")
MODULES_DECOMPRESSED = os.path.join(WORKING_DIR, "modules-decompressed.img")
MODULES_COMPRESSED = os.path.join(WORKING_DIR, "modules-compressed.img")
KERNEL = os.path.join(WORKING_DIR, "kernel.img")
PATCHED_MODULES_DECOMPRESSED = os.path.join(WORKING_DIR, "patched-modules-decompressed.img")
PATCHED_MODULES_COMPRESSED = os.path.join(WORKING_DIR, "patched-modules-compressed.img")

SECTOR_SIZE = 512
