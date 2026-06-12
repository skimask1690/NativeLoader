import os
import sys
import subprocess

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

if len(sys.argv) < 3 or sys.argv[1][0] == "-" or sys.argv[2][0] == "-":
    print(f"Usage: {os.path.basename(sys.argv[0])} <source.c> <output.bin> [-exe|-dll]")
    sys.exit(1)

args = [arg.lower() for arg in sys.argv]

input_c = sys.argv[1]
output_bin = sys.argv[2]
use_exe = "-exe" in args
use_dll = "-dll" in args

if not objcopy_found and not use_exe and not use_dll:
    print("[!] objcopy not found")
    sys.exit(1)

output_file = output_bin if use_exe or use_dll else "temp_compile.exe"

compile_cmd = [
    "x86_64-w64-mingw32-gcc",
    input_c,
    "-nostdlib", "-nostartfiles", "-ffreestanding",
    "-Wl,-subsystem,windows", "-e", "_start",
    "-Os", "-s", "-fno-ident", "-flto",
    "-Wl,--exclude-all-symbols",
    "-Wl,--no-insert-timestamp",
    "-fno-asynchronous-unwind-tables",
    "-mno-stack-arg-probe",
    "-o", output_file
]

if use_dll:
    compile_cmd.extend(["-shared"])
elif not use_exe and not use_dll:
    compile_cmd.extend(["-T", "linker.ld"])

try:
    result = subprocess.run(
        compile_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    filtered_stderr = ""
    for line in result.stderr.decode().splitlines():
        if ".text: section below image base" not in line:
            filtered_stderr += line + "\n"
    
    if filtered_stderr:
        print(filtered_stderr)

    if result.returncode != 0:
        sys.exit(1)

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
