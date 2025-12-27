import os
import sys
import subprocess

if len(sys.argv) < 3:
    print(f"Usage: {os.path.basename(sys.argv[0])} <source.c> <output.bin> [-exe | -dll] [-xor]")
    sys.exit(1)

args = [arg.lower() for arg in sys.argv]

input_c = sys.argv[1]
output_bin = sys.argv[2]
use_exe = "-exe" in args
use_dll = "-dll" in args
use_xor = "-xor" in args

output_file = output_bin if use_exe or use_dll else "temp_compile.exe"

compile_cmd = [
    "x86_64-w64-mingw32-gcc",
    "-s", input_c,
    "-nostdlib", "-nostartfiles", "-ffreestanding",
    "-fno-ident", "-Wl,-subsystem,windows", "-e", "_start",
    "-Os", "-fPIC", "-fno-asynchronous-unwind-tables",
    "-mno-stack-arg-probe", "-fno-stack-protector",
    "-o", output_file
]

if use_dll:
    compile_cmd.append("-shared")

if not use_exe and not use_dll:
    compile_cmd.extend(["-T", "linker.ld"])

if use_xor:
    compile_cmd.append("-DXOR")

try:
    subprocess.run(compile_cmd, check=True)
    if not use_exe and not use_dll:
        objcopy_cmd = [
            "objcopy",
            "-O", "binary",
            "--only-section=.text",
            output_file,
            output_bin
        ]
        subprocess.run(objcopy_cmd, check=True)
        os.remove(output_file)
        print(f"[+] Shellcode generated: {output_bin}")
    elif use_dll:
        print(f"[+] DLL generated: {output_file}")
    else:
        print(f"[+] Executable generated: {output_file}")
except subprocess.CalledProcessError:
    sys.exit(1)
