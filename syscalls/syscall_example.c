#include "direct_syscall.h"
//#include "indirect_syscall.h"

/* ================= Function pointer types ================= */
typedef NTSTATUS (NTAPI *NtCreateFile_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

/* ================= Strings ================= */
STRINGA(ntcreatefilea, "NtCreateFile");
STRINGW(filepath, "\\??\\C:\\temp\\test.txt")

/* ================= Entry point ================= */
__attribute__((section(".text.start")))
void _start(void) {
    SYSCALL_PREPARE(ntcreatefilea);
    NtCreateFile_t pNtCreateFile = SYSCALL_CALL(NtCreateFile_t);

    HANDLE hFile = NULL;
    IO_STATUS_BLOCK iosb = {0};

    UNICODE_STRING us;
    InitUnicodeString(&us, filepath);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    pNtCreateFile(&hFile, GENERIC_WRITE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE, NULL, 0);
}
