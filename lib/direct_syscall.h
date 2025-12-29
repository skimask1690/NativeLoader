#ifndef DIRECT_SYSCALL_H
#define DIRECT_SYSCALL_H

#include "winapi_loader.h"

/* ================= Macros ================= */
#define SYSCALL_PREPARE(name) do { ssn = ResolveSSN(name); } while (0)
#define SYSCALL_CALL(type) ((type)DirectSyscall)

/* ================= Strings ================= */
STRINGA(ntdll_dll, "ntdll.dll");
	
/* ================= Direct syscall core ================= */
static volatile DWORD ssn;

__attribute__((naked))
static NTSTATUS DirectSyscall(void) {
    __asm__ volatile(
        "mov %rcx, %r10\n"
        "mov ssn(%rip), %eax\n"
        "syscall\n"
        "ret\n"
    );
}

/* ================= SSN resolver ================= */
static DWORD ResolveSSN(const char* functionName) {

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

#endif // DIRECT_SYSCALL_H
