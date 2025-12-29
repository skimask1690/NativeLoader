#include "direct_syscall.h"
// #include "indirect_syscall.h"

/* ================= Function pointer types ================= */
typedef NTSTATUS (NTAPI *NtCreateFile_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

/* ================= Strings ================= */
STRINGW(filepath, "\\??\\C:\\Temp\\test.txt")
STRINGA(ntcreatefilea, "NtCreateFile");

/* ================= Entry point ================= */
__attribute__((section(".text.start")))
void _start(void) {
    SYSCALL_PREPARE(ntcreatefilea);
    NtCreateFile_t pNtCreateFile = SYSCALL_CALL(NtCreateFile_t);

    HANDLE hFile = NULL;
    IO_STATUS_BLOCK iosb = {0};

    USHORT len = 0;
    while (filepath[len]) len++;

    UNICODE_STRING us;
    us.Buffer = filepath;
    us.Length = len * sizeof(WCHAR);
    us.MaximumLength = us.Length + sizeof(WCHAR);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    pNtCreateFile(&hFile, GENERIC_WRITE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_NON_DIRECTORY_FILE, NULL, 0);
}
