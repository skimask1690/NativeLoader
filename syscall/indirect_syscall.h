#ifndef INDIRECT_SYSCALL_H
#define INDIRECT_SYSCALL_H

#include "winapi_loader.h"

/* ================= Macros ================= */
#define SYSCALL_PREPARE(name)           \
    do {                                \
        g_ssn  = ResolveSSN(name);      \
        g_stub = BuildIndirectSyscallStub(g_ssn); \
    } while (0)

#define SYSCALL_CALL(type) ((type)g_stub)

/* ================= Strings ================= */
STRINGA(ntdll_dll, "ntdll.dll");
STRINGA(ntallocvm,  "NtAllocateVirtualMemory");
STRINGA(ntprotectvm,"NtProtectVirtualMemory");

/* ================= Globals ================= */
static DWORD g_ssn;
static void *g_stub;

/* ================= SSN Resolver ================= */
static DWORD ResolveSSN(const char *name) {
    HMODULE ntdll = myGetModuleHandleA(ntdll_dll);
    unsigned char *f = (unsigned char *)myGetProcAddress(ntdll, name);

    if (f[0] == 0x4C && f[1] == 0x8B && f[2] == 0xD1 && f[3] == 0xB8)
        return *(DWORD *)(f + 4);

    for (int i = 0; i < 32; i++) {
        if (f[i] == 0xB8 && f[i + 5] == 0x0F && f[i + 6] == 0x05)
            return *(DWORD *)(f + i + 1);
    }

    return 0xFFFFFFFF;
}

/* ================= Indirect syscall core ================= */
static void *BuildSyscallStub(DWORD ssn) {
    NTSTATUS (NTAPI *NtAllocateVirtualMemory)(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    NTSTATUS (NTAPI *NtProtectVirtualMemory)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);

    HMODULE ntdll = myGetModuleHandleA(ntdll_dll);

    NtAllocateVirtualMemory = (void *)myGetProcAddress(ntdll, ntallocvm);
    NtProtectVirtualMemory = (void *)myGetProcAddress(ntdll, ntprotectvm);

    PVOID  base = NULL;
    SIZE_T size = 0x20;

    NtAllocateVirtualMemory((HANDLE)-1, &base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    unsigned char *p = (unsigned char *)base;

    p[0]  = 0x4C; // mov r10, rcx
    p[1]  = 0x8B;
    p[2]  = 0xD1;
    p[3]  = 0xB8; // mov eax, ssn 
    *(DWORD *)(p + 4) = ssn;
    p[8]  = 0x0F; // syscall 
    p[9]  = 0x05;
    p[10] = 0xC3; // ret 

    ULONG oldProt;
    NtProtectVirtualMemory((HANDLE)-1, &base, &size, PAGE_EXECUTE_READ, &oldProt);

    return base;
}

#endif // INDIRECT_SYSCALL_H
