#ifndef SYSCALL_H
#define SYSCALL_H

#include "winapi_loader.h"

/* ================= Strings ================= */
STRINGW(ntdll_path, "\\KnownDlls\\ntdll.dll");
#define ntdll_dll               HASH("ntdll.dll")
#define ntopensection           HASH("NtOpenSection")
#define ntcreatesection         HASH("NtCreateSection")
#define ntmapviewofsection      HASH("NtMapViewOfSection")
#define ntunmapviewofsection    HASH("NtUnmapViewOfSection")
#define ntclose                 HASH("NtClose")
#define ntallocatevirtualmemory HASH("NtAllocateVirtualMemory")
#define ntprotectvirtualmemory  HASH("NtProtectVirtualMemory")
#define ntfreevirtualmemory     HASH("NtFreeVirtualMemory")
#define ntdelayexecution        HASH("NtDelayExecution")
#define ntterminatethread       HASH("NtTerminateThread")
#define ntterminateprocess      HASH("NtTerminateProcess")

/* ================= Types ================= */
typedef NTSTATUS (NTAPI *NtUnmapViewOfSection_t)(HANDLE, PVOID);

typedef struct _NTDLL_DISK_CTX {
    PVOID base;
} NTDLL_DISK_CTX;

typedef struct _SYSCALL_STUB {
    struct _SYSCALL_STUB *next;
    DWORD ssn;
} SYSCALL_STUB;

typedef struct _SYSCALL_CTX {
    SYSCALL_STUB *head;
    NTDLL_DISK_CTX ntdll;
    HMODULE hNtdll;

    NTSTATUS (NTAPI *NtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    NTSTATUS (NTAPI *NtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    NTSTATUS (NTAPI *NtFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG);
} SYSCALL_CTX;

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

/* ================= API ================= */
SYSCALL_CTX *   CreateSyscallContext(void);
void            DestroySyscallContext(SYSCALL_CTX *ctx);
void *          BuildDirectSyscall(SYSCALL_CTX *ctx, DWORD ssn);
void            FreeSyscallStub(SYSCALL_CTX *ctx, PVOID stub);

NTDLL_DISK_CTX  MapNtdllFromDisk(HMODULE ntdll);
DWORD           ResolveSSN(NTDLL_DISK_CTX *ctx, unsigned int name_hash);
static BYTE *   GetExport(NTDLL_DISK_CTX *ctx, unsigned int target_hash);

/* ================= Macros ================= */
#define SYSCALL_INIT(ctx) \
    SYSCALL_CTX *ctx = CreateSyscallContext(); \
    DWORD ssn = 0

#define SYSCALL_PREPARE(ctx, name_hash) \
    do { \
        ssn = ResolveSSN(&ctx->ntdll, name_hash); \
    } while (0)

#define SYSCALL_CALL(ctx, type) ((type)BuildDirectSyscall(ctx, ssn))

#define SYSCALL_CLEANUP(ctx) \
    do { \
        SYSCALL_PREPARE(ctx, ntunmapviewofsection); \
        NtUnmapViewOfSection_t NtUnmapViewOfSection = SYSCALL_CALL(ctx, NtUnmapViewOfSection_t); \
        NtUnmapViewOfSection((HANDLE)-1, ctx->ntdll.base); \
        FreeSyscallStub(ctx, NtUnmapViewOfSection); \
        DestroySyscallContext(ctx); \
    } while(0)

#define SYSCALL_SLEEP(ctx, ms) \
    do { \
        SYSCALL_PREPARE(ctx, ntdelayexecution); \
        NtDelayExecution_t NtDelayExecution = SYSCALL_CALL(ctx, NtDelayExecution_t); \
        LARGE_INTEGER liInterval; \
        liInterval.QuadPart = -(LONGLONG)(ms) * 10000LL; \
        NtDelayExecution(FALSE, &liInterval); \
        FreeSyscallStub(ctx, NtDelayExecution); \
    } while(0)

#define SYSCALL_EXITTHREAD(ctx, status) \
    do { \
        SYSCALL_PREPARE(ctx, ntterminatethread); \
        NtTerminateThread_t NtTerminateThread = SYSCALL_CALL(ctx, NtTerminateThread_t); \
        NtTerminateThread((HANDLE)-2, (NTSTATUS)(status)); \
    } while (0)

#define SYSCALL_EXITPROCESS(ctx, status) \
    do { \
        SYSCALL_PREPARE(ctx, ntterminateprocess); \
        NtTerminateProcess_t NtTerminateProcess =  SYSCALL_CALL(ctx, NtTerminateProcess_t); \
        NtTerminateProcess((HANDLE)-1, (NTSTATUS)(status)); \
    } while (0)

/* ================= Implementation ================= */
SYSCALL_CTX *CreateSyscallContext(void) {
    SYSCALL_CTX *ctx = NULL;
    SIZE_T size = sizeof(*ctx);

    HMODULE ntdll = myGetModuleHandleH(ntdll_dll);

    NTSTATUS (NTAPI *NtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG) = (void *)myGetProcAddressH(ntdll, ntallocatevirtualmemory);
    NTSTATUS (NTAPI *NtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG) = (void *)myGetProcAddressH(ntdll, ntprotectvirtualmemory);
    NTSTATUS (NTAPI *NtFreeVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG) = (void *)myGetProcAddressH(ntdll, ntfreevirtualmemory);

    NtAllocateVirtualMemory((HANDLE)-1, (PVOID *)&ctx, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    ctx->head = NULL;
    ctx->hNtdll = ntdll;
    ctx->ntdll = MapNtdllFromDisk(ctx->hNtdll);

    ctx->NtAllocateVirtualMemory = NtAllocateVirtualMemory;
    ctx->NtProtectVirtualMemory = NtProtectVirtualMemory;
    ctx->NtFreeVirtualMemory = NtFreeVirtualMemory;

    return ctx;
}

void DestroySyscallContext(SYSCALL_CTX *ctx) {
    FreeSyscallStub(ctx, NULL);

    PVOID p = ctx; SIZE_T s = 0;
    ctx->NtFreeVirtualMemory((HANDLE)-1, &p, &s, MEM_RELEASE);
}

/* ================= Disk-backed NTDLL ================= */
static BYTE *GetExport(NTDLL_DISK_CTX *ctx, unsigned int target_hash) {
    BYTE *base = (BYTE *)ctx->base;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);

    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)
        (base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD *names = (DWORD *)(base + exp->AddressOfNames);
    WORD  *ords  = (WORD *)(base + exp->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char *fn = (const char *)(base + names[i]);
        if (runtime_hash(fn) == target_hash)
            return base + funcs[ords[i]];
    }
    return NULL;
}

NTDLL_DISK_CTX MapNtdllFromDisk(HMODULE ntdll) {
    NTDLL_DISK_CTX ctx = {0};

    NTSTATUS (NTAPI *NtOpenSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
    NTSTATUS (NTAPI *NtMapViewOfSection)(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
    NTSTATUS (NTAPI *NtClose)(HANDLE);

    UNICODE_STRING us;
    InitUnicodeString(&us, ntdll_path);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hSection;

    NtOpenSection = (void *)myGetProcAddressH(ntdll, ntopensection);
    NtOpenSection(&hSection, SECTION_MAP_READ, &oa);

    PVOID base = NULL;
    SIZE_T size = 0;

    NtMapViewOfSection = (void *)myGetProcAddressH(ntdll, ntmapviewofsection);
    NtMapViewOfSection(hSection, (HANDLE)-1, &base, 0, 0, NULL, &size, ViewShare, 0, PAGE_READONLY);

    NtClose = (void *)myGetProcAddressH(ntdll, ntclose);
    NtClose(hSection);

    ctx.base = base;
    return ctx;
}

/* ================= SSN resolution ================= */
DWORD ResolveSSN(NTDLL_DISK_CTX *ctx, unsigned int fn_hash) {
    BYTE *f = GetExport(ctx, fn_hash);

    if (f[0]==0x4C && f[1]==0x8B &&
        f[2]==0xD1 && f[3]==0xB8)
        return *(DWORD *)(f + 4);  // mov r10, rcx ; mov eax, imm32

    for (int i = 0; i < 32; i++)
        if (f[i]==0xB8 && f[i+5]==0x0F && f[i+6]==0x05)
            return *(DWORD *)(f + i + 1);  // mov eax, imm32 ; syscall

    return 0;
}

/* ================= Direct syscall stub ================= */
void *BuildDirectSyscall(SYSCALL_CTX *ctx, DWORD ssn) {
    SYSCALL_STUB *cur = ctx->head;
    while (cur) {
        if (cur->ssn == ssn)
            return (BYTE*)(cur + 1);
        cur = cur->next;
    }

    SIZE_T stub_size = 11;
    SIZE_T total_size = sizeof(SYSCALL_STUB) + stub_size;
    SYSCALL_STUB *node = NULL;
    ctx->NtAllocateVirtualMemory((HANDLE)-1, (PVOID*)&node, 0, &total_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    BYTE *p = (BYTE*)(node + 1);
    node->ssn = ssn;
    node->next = ctx->head;
    ctx->head = node;

    p[0] = 0x4C; p[1] = 0x8B; p[2] = 0xD1;  // mov r10, rcx
    p[3] = 0xB8; *(DWORD *)(p + 4) = ssn;   // mov eax, ssn
    p[8] = 0x0F; p[9] = 0x05;               // syscall
    p[10] = 0xC3;                           // ret

    ULONG oldProt;
    PVOID protect_addr = p;
    ctx->NtProtectVirtualMemory((HANDLE)-1, &protect_addr, &stub_size, PAGE_EXECUTE_READ, &oldProt);

    return p;
}

void FreeSyscallStub(SYSCALL_CTX *ctx, PVOID stub) {
    SYSCALL_STUB *prev = NULL;
    SYSCALL_STUB *cur  = ctx->head;

    while (cur) {
        SYSCALL_STUB *next = cur->next;
        if (stub == NULL || (BYTE*)(cur + 1) == stub) {
            if (prev)
                prev->next = next;
            else
                ctx->head = next;

            PVOID mb = cur;
            SIZE_T zs = 0;
            ctx->NtFreeVirtualMemory((HANDLE)-1, &mb, &zs, MEM_RELEASE);
        }
        else {
            prev = cur;
        }

        cur = next;
    }
}

#endif // SYSCALL_H
