#include "direct_syscall.h"
//#include "indirect_syscall.h"

/* ================= Function pointer types ================= */
typedef NTSTATUS (NTAPI *NtCreateFile_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *NtClose_t)(HANDLE);
typedef NTSTATUS (NTAPI *NtUnmapViewOfSection_t)(HANDLE, PVOID);
typedef NTSTATUS (NTAPI *NtFreeVirtualMemory_t)(HANDLE, PVOID *, PSIZE_T, ULONG);

/* ================= Strings ================= */
STRINGA(ntcreatefilea, "NtCreateFile");
STRINGA(ntclosea, "NtClose");
STRINGA(ntunmapviewa, "NtUnmapViewOfSection");
STRINGA(ntfreevma, "NtFreeVirtualMemory");
STRINGW(filepath, "\\??\\C:\\temp\\test.txt")

/* ================= Entry point ================= */
__attribute__((section(".text.start")))
void _start(void) {
    // Map disk-backed NTDLL
    NTDLL_DISK_CTX ntdll_ctx = MapNtdllFromDisk();
    PVOID ntdll_base = ntdll_ctx.base;

    // NtCreateFile
    SYSCALL_PREPARE(&ntdll_ctx, ntcreatefilea);
    NtCreateFile_t pNtCreateFile = SYSCALL_CALL(NtCreateFile_t);

    HANDLE hFile = NULL;
    IO_STATUS_BLOCK iosb = {0};
    UNICODE_STRING us; InitUnicodeString(&us, filepath);
    OBJECT_ATTRIBUTES oa; InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    pNtCreateFile(&hFile, GENERIC_WRITE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE, NULL, 0);

    // NtClose
    SYSCALL_PREPARE(&ntdll_ctx, ntclosea);
    NtClose_t pNtClose = SYSCALL_CALL(NtClose_t);
    pNtClose(hFile);

    // NtUnmapViewOfSection
    SYSCALL_PREPARE(&ntdll_ctx, ntunmapviewa);
    NtUnmapViewOfSection_t pNtUnmapViewOfSection = SYSCALL_CALL(NtUnmapViewOfSection_t);
    pNtUnmapViewOfSection((HANDLE)-1, ntdll_base);

    // NtFreeVirtualMemory
    SYSCALL_PREPARE(&ntdll_ctx, ntfreevma);
    NtFreeVirtualMemory_t pNtFreeVirtualMemory = SYSCALL_CALL(NtFreeVirtualMemory_t);

    SIZE_T size = 0;
    pNtFreeVirtualMemory((HANDLE)-1, &ntdll_base, &size, MEM_RELEASE);
}
