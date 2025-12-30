#ifndef INDIRECT_SYSCALL_H
#define INDIRECT_SYSCALL_H

#include "winapi_loader.h"

/* ================= Strings ================= */
STRINGA(ntdll_dll, "ntdll.dll");
STRINGW(ntdll_path, "\\SystemRoot\\System32\\ntdll.dll");

STRINGA(ntcreatefile, "NtCreateFile");
STRINGA(ntcreatesection, "NtCreateSection");
STRINGA(ntmapview, "NtMapViewOfSection");
STRINGA(ntclose, "NtClose");
STRINGA(ntallocvm, "NtAllocateVirtualMemory");
STRINGA(ntprotectvm, "NtProtectVirtualMemory");

/* ================= Types ================= */
typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

typedef struct _NTDLL_DISK_CTX {
    void  *base;
    SIZE_T size;
} NTDLL_DISK_CTX;

/* ================= Macros ================= */
#define LOAD_NTDLL \
    NTDLL_DISK_CTX ntdll_ctx = MapNtdllFromDisk(); \
    PVOID ntdll_base = ntdll_ctx.base; \
    DWORD g_ssn = 0; \
    void *g_syscall = NULL; \
    void *g_stub = NULL

#define SYSCALL_PREPARE(name) \
    do { \
        g_ssn = ResolveSSN(&ntdll_ctx, name); \
        g_syscall = ResolveSyscall(&ntdll_ctx, name); \
        g_stub = BuildIndirectSyscallStub(g_ssn, g_syscall); \
    } while (0)

#define SYSCALL_CALL(type) ((type)g_stub)

/* ================= Disk-backed NTDLL ================= */
static NTDLL_DISK_CTX MapNtdllFromDisk(void) {
    NTDLL_DISK_CTX ctx = {0};

    HMODULE ntdll = myGetModuleHandleA(ntdll_dll);

    UNICODE_STRING us;
    InitUnicodeString(&us, ntdll_path);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hFile;
    IO_STATUS_BLOCK iosb;

    NTSTATUS (NTAPI *NtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
        PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG) =
        (void *)myGetProcAddress(ntdll, ntcreatefile);

    NtCreateFile(&hFile, FILE_GENERIC_READ, &oa, &iosb, NULL,
                 FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
                 FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);

    HANDLE hSection;
    NTSTATUS (NTAPI *NtCreateSection)(PHANDLE, ACCESS_MASK,
        POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE) =
        (void *)myGetProcAddress(ntdll, ntcreatesection);

    NtCreateSection(&hSection, SECTION_MAP_READ, NULL, NULL,
                    PAGE_READONLY, SEC_IMAGE, hFile);

    PVOID base = NULL;
    SIZE_T size = 0;

    NTSTATUS (NTAPI *NtMapViewOfSection)(HANDLE, HANDLE, PVOID *,
        ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG) =
        (void *)myGetProcAddress(ntdll, ntmapview);

    NtMapViewOfSection(hSection, (HANDLE)-1, &base, 0, 0,
                       NULL, &size, ViewShare, 0, PAGE_READONLY);

    NTSTATUS (NTAPI *NtClose)(HANDLE) =
        (void *)myGetProcAddress(ntdll, ntclose);

    NtClose(hSection);
    NtClose(hFile);

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt =
        (IMAGE_NT_HEADERS *)((BYTE *)base + dos->e_lfanew);

    SIZE_T min_size = nt->OptionalHeader.SizeOfHeaders;

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER *sect =
            (IMAGE_SECTION_HEADER *)((BYTE *)nt +
             sizeof(IMAGE_NT_HEADERS) +
             i * sizeof(IMAGE_SECTION_HEADER));

        if ((sect->Characteristics & IMAGE_SCN_CNT_CODE) ||
            sect->VirtualAddress <=
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {

            SIZE_T end = sect->VirtualAddress + sect->Misc.VirtualSize;
            if (end > min_size)
                min_size = end;
        }
    }

    ctx.base = base;
    ctx.size = min_size;
    return ctx;
}

/* ================= PE helpers ================= */
static BYTE *GetExport(NTDLL_DISK_CTX *ctx, const char *name) {
    BYTE *base = (BYTE *)ctx->base;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt =
        (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);

    IMAGE_EXPORT_DIRECTORY *exp =
        (IMAGE_EXPORT_DIRECTORY *)(base +
         nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD *names = (DWORD *)(base + exp->AddressOfNames);
    WORD  *ords  = (WORD *)(base + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char *n = (char *)(base + names[i]);
        const char *a = n;
        const char *b = name;

        while (*a && *b && *a == *b) { a++; b++; }
        if (!*a && !*b)
            return base + funcs[ords[i]];
    }

    return NULL;
}

/* ================= SSN & syscall resolution ================= */
static DWORD ResolveSSN(NTDLL_DISK_CTX *ctx, const char *name) {
    BYTE *f = GetExport(ctx, name);

    if (f[0] == 0x4C && f[1] == 0x8B &&
        f[2] == 0xD1 && f[3] == 0xB8)
        return *(DWORD *)(f + 4);

    for (int i = 0; i < 32; i++)
        if (f[i] == 0xB8 &&
            f[i + 5] == 0x0F &&
            f[i + 6] == 0x05)
            return *(DWORD *)(f + i + 1);

    return 0xFFFFFFFF;
}

static void *ResolveSyscall(NTDLL_DISK_CTX *ctx, const char *name) {
    BYTE *f = GetExport(ctx, name);

    for (int i = 0; i < 32; i++)
        if (f[i] == 0x0F && f[i + 1] == 0x05)
            return f + i;

    return NULL;
}

/* ================= Indirect syscall stub ================= */
static void *BuildIndirectSyscallStub(DWORD ssn, void *syscall_addr) {
    NTSTATUS (NTAPI *NtAllocateVirtualMemory)(HANDLE, PVOID *,
        ULONG_PTR, PSIZE_T, ULONG, ULONG) =
        (void *)myGetProcAddress(
            myGetModuleHandleA(ntdll_dll), ntallocvm);

    NTSTATUS (NTAPI *NtProtectVirtualMemory)(HANDLE, PVOID *,
        PSIZE_T, ULONG, PULONG) =
        (void *)myGetProcAddress(
            myGetModuleHandleA(ntdll_dll), ntprotectvm);

    PVOID base = NULL;
    SIZE_T size = 22;

    NtAllocateVirtualMemory((HANDLE)-1, &base, 0, &size,
                            MEM_COMMIT | MEM_RESERVE,
                            PAGE_READWRITE);

    BYTE *p = (BYTE *)base;

    p[0] = 0x4C; p[1] = 0x8B; p[2] = 0xD1;  // mov r10, rcx
    p[3] = 0xB8; *(DWORD *)(p + 4) = ssn;   // mov eax, ssn
    p[8] = 0xFF; p[9] = 0x25;               // jmp [rip+0]
    *(DWORD *)(p + 10) = 0;
    *(void **)(p + 14) = syscall_addr;

    ULONG oldProt;
    NtProtectVirtualMemory((HANDLE)-1, &base, &size,
                           PAGE_EXECUTE_READ, &oldProt);

    return base;
}

#endif // INDIRECT_SYSCALL_H
