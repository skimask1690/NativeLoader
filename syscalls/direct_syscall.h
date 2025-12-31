#ifndef DIRECT_SYSCALL_H
#define DIRECT_SYSCALL_H

#include "winapi_loader.h"

/* ================= Strings ================= */
STRINGA(ntdll_dll, "ntdll.dll");
STRINGW(ntdll_path, "\\SystemRoot\\System32\\ntdll.dll");

STRINGA(ntcreatefile, "NtCreateFile");
STRINGA(ntcreatesection, "NtCreateSection");
STRINGA(ntmapviewofsection, "NtMapViewOfSection");
STRINGA(ntunmapviewofsection, "NtUnmapViewOfSection");
STRINGA(ntclose, "NtClose");
STRINGA(ntallocatevirtualmemory, "NtAllocateVirtualMemory");
STRINGA(ntprotectvirtualmemory, "NtProtectVirtualMemory");
STRINGA(ntfreevirtualmemory, "NtFreeVirtualMemory");

/* ================= Types ================= */
typedef NTSTATUS (NTAPI *NtUnmapViewOfSection_t)(HANDLE, PVOID);

typedef struct _NTDLL_DISK_CTX {
    PVOID base;
    SIZE_T size;
} NTDLL_DISK_CTX;

typedef struct _SYSCALL_STUB {
    struct _SYSCALL_STUB *next;
    PVOID base;
    SIZE_T size;
} SYSCALL_STUB;

typedef struct _SYSCALL_CTX {
    SYSCALL_STUB *head;
} SYSCALL_CTX;

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

/* ================= API ================= */
SYSCALL_CTX *   CreateSyscallContext(void);
void            DestroySyscallContext(SYSCALL_CTX *ctx);
void *          BuildDirectSyscall(SYSCALL_CTX *ctx, DWORD ssn);
void            FreeSyscallStub(SYSCALL_CTX *ctx, PVOID specific_stub);

NTDLL_DISK_CTX  MapNtdllFromDisk(void);
DWORD           ResolveSSN(NTDLL_DISK_CTX *ctx, const char *name);

/* ================= Macros ================= */
#define SYSCALL_INIT \
    SYSCALL_CTX *ctx = CreateSyscallContext();   \
    NTDLL_DISK_CTX ntdll_ctx = MapNtdllFromDisk(); \
    DWORD ssn = 0

#define SYSCALL_PREPARE(ctx, name) \
    do { \
        ssn = ResolveSSN(&ntdll_ctx, name); \
    } while (0)

#define SYSCALL_CALL(ctx, type) ((type)BuildDirectSyscall(ctx, ssn))

#define SYSCALL_CLEANUP(ctx) \
    do { \
        SYSCALL_PREPARE(ctx, ntunmapviewofsection); \
        NtUnmapViewOfSection_t NtUnmapViewOfSection = SYSCALL_CALL(ctx, NtUnmapViewOfSection_t); \
        NtUnmapViewOfSection((HANDLE)-1, ntdll_ctx.base); \
        FreeSyscallStub(ctx, NtUnmapViewOfSection); \
		DestroySyscallContext(ctx);                 \
    } while(0)

/* ================= Implementation ================= */
SYSCALL_CTX *CreateSyscallContext(void) {
    SYSCALL_CTX *ctx = NULL;
    SIZE_T size = sizeof(*ctx);

    NTSTATUS (NTAPI *NtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG) = (void *)myGetProcAddress(myGetModuleHandleA(ntdll_dll), ntallocatevirtualmemory);
    NtAllocateVirtualMemory((HANDLE)-1, (PVOID *)&ctx, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (ctx) ctx->head = NULL;
    return ctx;
}

void DestroySyscallContext(SYSCALL_CTX *ctx) {
    FreeSyscallStub(ctx, NULL);

    NTSTATUS (NTAPI *NtFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG) = (void *)myGetProcAddress(myGetModuleHandleA(ntdll_dll), ntfreevirtualmemory);

    PVOID p = ctx; SIZE_T s = 0;
    NtFreeVirtualMemory((HANDLE)-1, &p, &s, MEM_RELEASE);
}

/* ================= Disk-backed NTDLL ================= */
static BYTE *GetExport(NTDLL_DISK_CTX *ctx, const char *name) {
    BYTE *base = (BYTE*)ctx->base;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY*)(base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD *names = (DWORD*)(base + exp->AddressOfNames);
    WORD  *ords  = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD*)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *a = (char*)(base + names[i]), *b = name;
        while (*a && *b && *a == *b) { a++; b++; }
        if (!*a && !*b) return base + funcs[ords[i]];
    }
    return NULL;
}

NTDLL_DISK_CTX MapNtdllFromDisk(void) {
    NTDLL_DISK_CTX ctx = {0};

    NTSTATUS (NTAPI *NtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
    NTSTATUS (NTAPI *NtCreateSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
    NTSTATUS (NTAPI *NtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
    NTSTATUS (NTAPI *NtClose)(HANDLE);

    HMODULE ntdll = myGetModuleHandleA(ntdll_dll);
    NtCreateFile       = (void*)myGetProcAddress(ntdll, ntcreatefile);
    NtCreateSection    = (void*)myGetProcAddress(ntdll, ntcreatesection);
    NtMapViewOfSection = (void*)myGetProcAddress(ntdll, ntmapviewofsection);
    NtClose            = (void*)myGetProcAddress(ntdll, ntclose);

    UNICODE_STRING us; InitUnicodeString(&us, ntdll_path);
    OBJECT_ATTRIBUTES oa; InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hFile; IO_STATUS_BLOCK iosb;
    NtCreateFile(&hFile, FILE_GENERIC_READ, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);

    HANDLE hSection;
    NtCreateSection(&hSection, SECTION_MAP_READ, NULL, NULL, PAGE_READONLY, SEC_IMAGE, hFile);

    PVOID base = NULL; SIZE_T size = 0;
    NtMapViewOfSection(hSection, (HANDLE)-1, &base, 0, 0, NULL, &size, ViewShare, 0, PAGE_READONLY);

    NtClose(hSection); NtClose(hFile);

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS*)((BYTE*)base + dos->e_lfanew);

    SIZE_T min_size = nt->OptionalHeader.SizeOfHeaders;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER *sect = (IMAGE_SECTION_HEADER*)((BYTE*)nt + sizeof(IMAGE_NT_HEADERS) + i * sizeof(IMAGE_SECTION_HEADER));
        if ((sect->Characteristics & IMAGE_SCN_CNT_CODE) || sect->VirtualAddress <= nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
            SIZE_T end = sect->VirtualAddress + sect->Misc.VirtualSize;
            if (end > min_size) min_size = end;
        }
    }

    ctx.base = base; ctx.size = min_size;
    return ctx;
}

/* ================= SSN resolution ================= */
DWORD ResolveSSN(NTDLL_DISK_CTX *ctx, const char *name) {
    BYTE *f = GetExport(ctx, name);

    if (f[0]==0x4C && f[1]==0x8B && f[2]==0xD1 && f[3]==0xB8)
        return *(DWORD*)(f + 4);

    for (int i = 0; i < 32; i++)
        if (f[i]==0xB8 && f[i+5]==0x0F && f[i+6]==0x05)
            return *(DWORD*)(f + i + 1);

    return 0xFFFFFFFF;
}

/* ================= Direct syscall stub ================= */
void *BuildDirectSyscall(SYSCALL_CTX *ctx, DWORD ssn) {
    NTSTATUS (NTAPI *NtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG) = (void *)myGetProcAddress(myGetModuleHandleA(ntdll_dll), ntallocatevirtualmemory);
    NTSTATUS (NTAPI *NtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG) = (void *)myGetProcAddress(myGetModuleHandleA(ntdll_dll), ntprotectvirtualmemory);

    SYSCALL_STUB *node = NULL; SIZE_T node_sz = sizeof(*node);
    NtAllocateVirtualMemory((HANDLE)-1, (PVOID*)&node, 0, &node_sz, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);

    PVOID base = NULL; SIZE_T size = 11;
    NtAllocateVirtualMemory((HANDLE)-1, &base, 0, &size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);

    BYTE *p = (BYTE *)base;
    p[0] = 0x4C; p[1] = 0x8B; p[2] = 0xD1;  // mov r10, rcx
    p[3] = 0xB8; *(DWORD *)(p + 4) = ssn;   // mov eax, ssn
    p[8] = 0x0F; p[9] = 0x05;               // syscall
    p[10] = 0xC3;                           // ret

    ULONG oldProt;
    NtProtectVirtualMemory((HANDLE)-1, &base, &size, PAGE_EXECUTE_READ, &oldProt);

    node->base = base; node->size = size;
    node->next = ctx->head; ctx->head = node;

    return base;
}

void FreeSyscallStub(SYSCALL_CTX *ctx, PVOID specific_stub) {

    NTSTATUS (NTAPI *NtFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG) = (void *)myGetProcAddress(myGetModuleHandleA(ntdll_dll), ntfreevirtualmemory);

    SYSCALL_STUB *prev = NULL;
    SYSCALL_STUB *cur  = ctx->head;

    while (cur) {
        SYSCALL_STUB *next = cur->next;
        if (specific_stub == NULL || cur->base == specific_stub) {
            if (cur->base) {
                PVOID mb = cur->base; SIZE_T zs = 0;
                NtFreeVirtualMemory((HANDLE)-1, &mb, &zs, MEM_RELEASE);
            }
            PVOID nb = cur; SIZE_T nz = 0;
            NtFreeVirtualMemory((HANDLE)-1, &nb, &nz, MEM_RELEASE);

            if (prev) prev->next = next;
            else        ctx->head = next;
        } else {
            prev = cur;
        }
        cur = next;
    }
}

#endif // DIRECT_SYSCALL_H
