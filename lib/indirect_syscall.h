#ifndef INDIRECT_SYSCALL_H
#define INDIRECT_SYSCALL_H

#include "winapi_loader.h"

/* ================= Macros ================= */
#define SYSCALL_PREPARE(name) do { stub_addr = GetNtStubAddress(name); ssn = ResolveSSN(name); } while (0)
#define SYSCALL_CALL(type) ((type)IndirectSyscall)

/* ================= Function pointer types ================= */
typedef NTSTATUS (NTAPI *NtCreateFile_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *NtReadFile_t)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *NtFreeVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG);
typedef NTSTATUS (NTAPI *NtQueryInformationFile_t)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
typedef NTSTATUS (NTAPI *NtClose_t)(HANDLE);

/* ================= Strings ================= */
STRINGA(ntdll_dll, "ntdll.dll");
STRINGA(ntcreatefile, "NtCreateFile");
STRINGA(ntreadfile, "NtReadFile");
STRINGA(ntclose, "NtClose");
STRINGW(path, "\\SystemRoot\\System32\\ntdll.dll");
STRINGA(ntqueryinfo, "NtQueryInformationFile");
STRINGA(ntallocvm, "NtAllocateVirtualMemory");
STRINGA(ntfreevm, "NtFreeVirtualMemory");

/* ================= Helpers ================= */
static volatile DWORD ssn;
void* stub_addr;

static void* GetNtStubAddress(const char* name) {
    HMODULE hNtdll = myGetModuleHandleA(ntdll_dll);
    BYTE* base = (BYTE*)myGetProcAddress(hNtdll, name);

    for (int i = 0; i < 64; i++) {
        if (base[i] == 0x0F && base[i+1] == 0x05) {
            return (void*)(base + i);
        }
    }
    return NULL;
}

/* ================= Indirect syscall core ================= */
__attribute__((naked))
static NTSTATUS IndirectSyscall(void) {
    __asm__ volatile(
        "mov %rcx, %r10\n"
        "mov ssn(%rip), %eax\n"
        "jmp *stub_addr(%rip)\n"
    );
}

/* ================= SSN resolver ================= */
static DWORD ResolveSSN(const char* functionName) {
	char stackbuf[10];

    char* ntdll_dll = stackbuf;
#ifdef XOR
    ntdll_dll[0] = 'n'^XOR_KEY(9); ntdll_dll[1] = 't'^XOR_KEY(9);
    ntdll_dll[2] = 'd'^XOR_KEY(9); ntdll_dll[3] = 'l'^XOR_KEY(9);
    ntdll_dll[4] = 'l'^XOR_KEY(9); ntdll_dll[5] = '.'^XOR_KEY(9);
    ntdll_dll[6] = 'd'^XOR_KEY(9); ntdll_dll[7] = 'l'^XOR_KEY(9);
    ntdll_dll[8] = 'l'^XOR_KEY(9); ntdll_dll[9] = 0;
    xor_decode(ntdll_dll);
#else
    ntdll_dll[0] = 'n'; ntdll_dll[1] = 't'; ntdll_dll[2] = 'd';
    ntdll_dll[3] = 'l'; ntdll_dll[4] = 'l'; ntdll_dll[5] = '.';
    ntdll_dll[6] = 'd'; ntdll_dll[7] = 'l'; ntdll_dll[8] = 'l';
    ntdll_dll[9] = 0;
#endif

    HMODULE hNtdll = myGetModuleHandleA(ntdll_dll);
    BYTE* funcBytes = (BYTE*)myGetProcAddress(hNtdll, functionName);

    // first 4 bytes: mov r10, rcx ; mov eax, imm32
    if (funcBytes[0] == 0x4C &&
        funcBytes[1] == 0x8B &&
        funcBytes[2] == 0xD1 &&
        funcBytes[3] == 0xB8)
    {
        return *(DWORD*)(funcBytes + 4);
    }

    // fallback: search for mov eax, imm32 + syscall
    for (int i = 0; i < 32; i++) {
        if (funcBytes[i] == 0xB8 &&
            funcBytes[i + 5] == 0x0F &&
            funcBytes[i + 6] == 0x05)
        {
            return *(DWORD*)(funcBytes + i + 1);
        }
    }

    return 0xFFFFFFFF;
}

/* ================= Disk bootstrap via ntdll ================= */
static void ReadNtdllTextSection(BYTE** ImageBase, DWORD* ImageSize) {
    SYSCALL_PREPARE(ntcreatefile);
    NtCreateFile_t pNtCreateFile = SYSCALL_CALL(NtCreateFile_t);

    SYSCALL_PREPARE(ntreadfile);
    NtReadFile_t pNtReadFile = SYSCALL_CALL(NtReadFile_t);

    SYSCALL_PREPARE(ntclose);
    NtClose_t pNtClose = SYSCALL_CALL(NtClose_t);

    SYSCALL_PREPARE(ntqueryinfo);
    NtQueryInformationFile_t pNtQueryInformationFile = SYSCALL_CALL(NtQueryInformationFile_t);

    SYSCALL_PREPARE(ntallocvm);
    NtAllocateVirtualMemory_t pNtAllocateVirtualMemory = SYSCALL_CALL(NtAllocateVirtualMemory_t);

    SYSCALL_PREPARE(ntfreevm);
    NtFreeVirtualMemory_t pNtFreeVirtualMemory = SYSCALL_CALL(NtFreeVirtualMemory_t);

    HANDLE hFile = NULL;
    IO_STATUS_BLOCK iosb;
    FILE_STANDARD_INFORMATION fsi;

    UNICODE_STRING us;
    us.Buffer = path;
    us.Length = sizeof(path) - sizeof(WCHAR);
    us.MaximumLength = sizeof(path);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    pNtCreateFile(&hFile, GENERIC_READ, &oa, &iosb, NULL,
                  FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
                  FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);

    pNtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation);

    SIZE_T fileSize = (SIZE_T)fsi.EndOfFile.QuadPart;
    PVOID fileBuffer = NULL;

    pNtAllocateVirtualMemory((HANDLE)-1, &fileBuffer, 0, &fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    pNtReadFile(hFile, NULL, NULL, NULL, &iosb, fileBuffer, (ULONG)fileSize, NULL, NULL);
    pNtClose(hFile);

    BYTE* base = (BYTE*)fileBuffer;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    PVOID textSection = NULL;
    SIZE_T textSize = 0;

    int i = 0;
    while (i < (int)nt->FileHeader.NumberOfSections) {
        if (sec->Characteristics & IMAGE_SCN_CNT_CODE) {
            textSize = sec->SizeOfRawData;
            pNtAllocateVirtualMemory((HANDLE)-1, &textSection, 0, &textSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            BYTE* src = base + sec->PointerToRawData;
            BYTE* dst = (BYTE*)textSection;
            SIZE_T k = 0;
            while (k < textSize) {
                dst[k] = src[k];
                k++;
            }
            break;
        }
        sec++;
        i++;
    }

    SIZE_T zero = 0;
    pNtFreeVirtualMemory((HANDLE)-1, &fileBuffer, &zero, MEM_RELEASE);

    *ImageBase = (BYTE*)textSection;
    *ImageSize = (DWORD)textSize;
}

#endif // INDIRECT_SYSCALL_H
