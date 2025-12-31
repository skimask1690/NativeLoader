#include "direct_syscall.h"
// #include "indirect_syscall.h"

/* ================= Function pointer types ================= */
typedef NTSTATUS (NTAPI *NtCreateFile_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *NtClose_t)(HANDLE);

/* ================= Strings ================= */
STRINGW(filepath, "\\??\\C:\\temp\\test.txt");

/* ================= Entry point ================= */
__attribute__((section(".text.start")))
void _start(void)
{
    SYSCALL_INIT(ctx);

    // NtCreateFile
    SYSCALL_PREPARE(ctx, ntcreatefile);
    NtCreateFile_t NtCreateFile = SYSCALL_CALL(ctx, NtCreateFile_t);

    HANDLE hFile = NULL;
    IO_STATUS_BLOCK iosb = {0};

    UNICODE_STRING us;
    InitUnicodeString(&us, filepath);

    OBJECT_ATTRIBUTES oa;
    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = &us;
    oa.Attributes = OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    NtCreateFile(&hFile, GENERIC_WRITE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE, NULL, 0);
    FreeSyscallStub(ctx, NtCreateFile);

    // NtClose
    SYSCALL_PREPARE(ctx, ntclose);
    NtClose_t NtClose = SYSCALL_CALL(ctx, NtClose_t);
    NtClose(hFile);
    FreeSyscallStub(ctx, NtClose);

    SYSCALL_CLEANUP(ctx); 
}
