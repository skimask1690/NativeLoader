#include "winapi_loader.h"

typedef NTSTATUS (NTAPI *NtCreateMutant_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN);
typedef NTSTATUS (NTAPI *NtClose_t)(HANDLE);

#define ntcreatemutant HASH("NtCreateMutant")
#define ntclose HASH("NtClose")

#define MUTEX_NAME L"MyUniqueProgramMutex"

typedef struct _PROCESS_SESSION_INFORMATION {
    ULONG SessionId;
} PROCESS_SESSION_INFORMATION;

HANDLE CreateSessionMutex(HMODULE hNtdll) {
    NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)myGetProcAddressH(hNtdll, ntqueryinformationprocess);
    NtCreateMutant_t NtCreateMutant = (NtCreateMutant_t)myGetProcAddressH(hNtdll, ntcreatemutant);

    NtTerminateProcess_t NtTerminateProcess = (NtTerminateProcess_t)myGetProcAddressH(hNtdll, ntterminateprocess);

    PROCESS_SESSION_INFORMATION psi;
    NtQueryInformationProcess((HANDLE)-1, ProcessSessionInformation, &psi, sizeof(psi), NULL);

    STRINGW(prefix, "\\Sessions\\");
    STRINGW(mutex, "\\BaseNamedObjects\\" MUTEX_NAME);

    int prefix_len = 0;
    while (prefix[prefix_len]) prefix_len++;

    int mutex_len = 0;
    while (mutex[mutex_len]) mutex_len++;

    int sid_len = 0;
    ULONG temp = psi.SessionId;
    do { temp /= 10; sid_len++; } while (temp > 0);

    wchar_t path[prefix_len + sid_len + mutex_len + 1];
    wchar_t *p = path;

    for (int i = 0; i < prefix_len; i++) *p++ = prefix[i];

    wchar_t *digit_ptr = p + sid_len;
    ULONG v = psi.SessionId;
    do { *(--digit_ptr) = L'0' + (v % 10); v /= 10; } while (v > 0);
    p += sid_len;

    for (int i = 0; i < mutex_len; i++) *p++ = mutex[i];
    *p = L'\0';

    UNICODE_STRING name;
    name.Buffer = path;
    name.Length = (USHORT)((p - path) * sizeof(wchar_t));
    name.MaximumLength = sizeof(path);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hMutex = NULL;
    NTSTATUS status = NtCreateMutant(&hMutex, 0, &oa, FALSE);

    if (!NT_SUCCESS(status))
        NtTerminateProcess((HANDLE)-1, 0);

    return hMutex;
}

__attribute__((section(".text.start")))
int _start(void) {
    HMODULE hNtdll = myGetModuleHandleH(ntdll_dll);
    NtClose_t NtClose = (NtClose_t)myGetProcAddressH(hNtdll, ntclose);

    HANDLE hMutex = CreateSessionMutex(hNtdll);

    STRINGA(hello_str, "Hello from single instance!\n");
    STDOUT_WRITE(hello_str);
    mySleep(60000);

    NtClose(hMutex);
}
