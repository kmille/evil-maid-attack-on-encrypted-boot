from typing import Optional
import os.path
from subprocess import Popen, PIPE
import struct
from hashlib import md5
import glob
from dataclasses import dataclass
import hashlib

from constants import MODULE_DIR, WORKING_DIR, MODULES_DECOMPRESSED, PATCHED_CORE, PATCHED_MODULES_COMPRESSED, PATCHED_MODULES_DECOMPRESSED


#def find_bytes_offset(target: bytes, search: bytes) -> int:
#    for offset in range(len(target)):
#        if target[offset:].startswith(search):
#            return offset
#    return -1
#
#
#assert find_bytes_offset(b"ABC", b"blubb") == -1
#assert find_bytes_offset(b"123AB", b"ABC") == -1
#assert find_bytes_offset(b"ABCDEF", b"ABC") == 0
#assert find_bytes_offset(b"ABABC", b"ABC") == 2


def find_bytes_offset(target: bytes, search: bytes, miss_toleration: int) -> int:
    for offset in range(len(target)):
        if starts_with_toleration(target[offset:], search, miss_toleration):
            return offset
    return -1


def starts_with_toleration(target: bytes, search: bytes, miss_toleration: int):
    #print(f"Comparing: is {search} in {target}")
    if len(search) > len(target):
        return False
    for i in range(len(search)):
        if target[i] != search[i]:
            if miss_toleration == 0:
                return False
            #print(f"{target[i]} is not {search[i]}. ignoring .. (miss_toleration={miss_toleration})")
            miss_toleration -= 1
    return True


assert find_bytes_offset(b"ABC", b"blubb", 0) == -1
assert find_bytes_offset(b"ABC", b"blubb", 5) == -1
assert find_bytes_offset(b"ABCDE", b"blubb", 5) == 0
assert find_bytes_offset(b"ABCDE", b"blubb", 4) == -1
assert find_bytes_offset(b"ABCABCDEF", b"ABCDEF", 0) == 3
assert find_bytes_offset(b"ABCABCDEF", b"ABCDEX", 0) == -1
assert find_bytes_offset(b"ABCABCDEF", b"ABCDEX", 1) == 3

#assert find_bytes_offset2(b"123AB", b"ABC") == -1
#assert find_bytes_offset2(b"ABCDEF", b"ABC") == 0
#assert find_bytes_offset2(b"ABABC", b"ABC") == 2


def cmd(x: str) -> str:
    print(f"Executing '{x}'")
    p = Popen(x, shell=True, stdout=PIPE, stderr=PIPE)
    p.wait()
    stdout_b, stderr = p.communicate()
    stdout = stdout_b.decode()
    #assert p.returncode == 0, stderr.decode()
    if len(stdout.strip()) != 0:
        print(stdout)
    return stdout


def parse_module_type(type: bytes):
    """
    types = {
            0: 'OBJ_TYPE_ELF',
            1: 'OBJ_TYPE_MEMDISK',
            2: 'OBJ_TYPE_CONFIG',
            3: 'OBJ_TYPE_PREFIX',
            4: 'OBJ_TYPE_PUBKEY',
            5: 'OBJ_TYPE_DTB',
            6: 'OBJ_TYPE_DISABLE_SHIM_LOCK'
    }
    """
    module_type = struct.unpack("<i", type)[0]
    #return types[module_type]
    return module_type


def read_all_modules_from_disk() -> dict[str, str]:
    data = {}

    for file in glob.glob(f"{MODULE_DIR}//mods-*/*"):
        with open(file, "rb") as f:
            hash = md5(f.read()).hexdigest()
            data[hash] = file
    return data


module_hashes = read_all_modules_from_disk()


@dataclass
class GrubModule:
    type: int
    size: int
    content: bytes = b""
    md5: str = ""
    filename: str = ""

    def __post_init__(self):
        self.md5 = hashlib.md5(self.content).hexdigest()
        self.filename = module_hashes.get(self.md5, '')

    def __str__(self):
        if self.type != 0:
            return f"grub_module: type={self.type} size={hex(self.size):<7} md5={self.md5} filename={self.filename} content={self.content}"
        else:
            return f"grub_module: type={self.type} size={hex(self.size):<7} md5={self.md5} filename={self.filename}"

    def serialize(self) -> bytes:
        return struct.pack("<I", self.type) + \
               struct.pack("<I", self.size) + \
               self.content


def patch_diskboot_img(patched_image_size):
    print("Patching diskboot image")
    sectors_we_need = patched_image_size - 512 + 512 - 1 >> 9
    with open(PATCHED_CORE, "r+b") as f:
        f.seek(0x01fc)
        f.write(struct.pack("<H", sectors_we_need))
    print(f"Updated sector length: we need {hex(sectors_we_need)} sectors")


def patch_decompress_img():
    print("Patching decompress image")
    size_compressed = os.path.getsize(PATCHED_MODULES_COMPRESSED)
    size_decompressed = os.path.getsize(PATCHED_MODULES_DECOMPRESSED)
    print(f"compressed_size={hex(size_compressed)} decompressed_size={hex(size_decompressed)}")
    offset, _ = find_image_in_blob(PATCHED_CORE, "lzma_decompress.img", 6)
    with open(PATCHED_CORE, "r+b") as f:
        f.seek(offset+8)
        f.write(struct.pack("<I", size_compressed))
        f.write(struct.pack("<I", size_decompressed))
    print("Done patching decompress image")


def parse_module(offset: int) -> Optional[GrubModule]:
    # module = grub_module_header | module_image
    """ in include/grub/kernel.h
    /* The module header.  */
    struct grub_module_header
    {
      /* The type of object.  */
      grub_uint32_t type;
      /* The size of object (including this header).  */
      grub_uint32_t size;
    };
    """
    with open(MODULES_DECOMPRESSED, "rb") as f:
        f.seek(offset)
        data = f.read(4)
        # module_type is 0 for a an elf object
        module_type = parse_module_type(data)
        module_size = struct.unpack("<i", f.read(4))[0]
        # module_size includes the header size (4 bytes size and 4 bytes type)
        module_content = f.read(module_size - 8)
    module = GrubModule(type=module_type, size=module_size, content=module_content)
    return module


def find_image_in_blob(blob_location: str, search_image: str, miss_toleration: int) -> tuple[int, int]:
    # find a module in core.img - helpful to find the underlying os
    print(f"Looking for {search_image} in {blob_location}")
    offset = -1
    with open(blob_location, "rb") as f:
        core_img = f.read()
    for image_path in glob.glob(f"{MODULE_DIR}/mods-*/{search_image}"):
        print(f" Trying '{image_path}'")
        with open(image_path, "rb") as f:
            disk_img = f.read()
        offset = find_bytes_offset(core_img, disk_img, miss_toleration)
        if offset != -1:
            print(f"Found {image_path} at offset {hex(offset)} (size {hex(len(disk_img))})")
            break
    # BUG: what if we have multiple hits
    print("")
    assert offset != -1
    return offset, len(disk_img)


def parse_grub_modules(module_offset: int) -> list[GrubModule]:
    all_modules: list[GrubModule] = []
    print(f"Parsing modules starting at offset {hex(module_offset)}")
    while True:
        module = parse_module(module_offset)
        print(module)
        all_modules.append(module)
        module_offset += module.size
        # mkimage.c adds type 3 as last module
        if module.type == 3:
            return all_modules


def parse_diskboot_img(core_img: str) -> tuple[int, int]:
    print(f"Parsing diskboot.img in {core_img}")
    # grub_pc_bios_boot_blocklist is defined in grub/include/grub/offsets.h
    with open(core_img, "rb") as f:
        # 0x1f4 = 500 = 512 - 12 (at the end of diskboot.img)
        f.seek(0x1f4)
        # sector_next_image: is usually 2 and means next block (as diskboot.img is the first one)
        sector_next_image = struct.unpack("<Q", f.read(8))[0]
        # size: size of core.img including diskboot.img (e.g. 0x6a * sector_size)
        size = struct.unpack("<H", f.read(2))[0]
        segment = struct.unpack("<H", f.read(2))[0]
    print(f"grub_pc_bios_boot_blocklist: sector_next_image={hex(sector_next_image)} size={hex(size)} segment={hex(segment)}\n")
    # sector_next_image refers to the disk offset (we dont have a mbr here -1)
    return sector_next_image - 1, size


def clean_working_directory() -> None:
    print(f"Cleaning working directory {WORKING_DIR}")
    for file in glob.glob(f"{WORKING_DIR}/*.img"):
        os.remove(file)
    for file in glob.glob(f"{WORKING_DIR}/*.dd"):
        os.remove(file)
