#include "winapi_loader.h"

typedef NTSTATUS (NTAPI *NtCreateMutant_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN);
typedef NTSTATUS (NTAPI *NtClose_t)(HANDLE);

#define ntcreatemutant HASH("NtCreateMutant")
#define ntclose HASH("NtClose")

STRINGW(prefix, "\\Sessions\\")
STRINGW(mutex, "\\BaseNamedObjects\\MyUniqueProgramMutex")

typedef struct _PROCESS_SESSION_INFORMATION {
    ULONG SessionId;
} PROCESS_SESSION_INFORMATION;

__attribute__((section(".text.start")))
int _start(void) {
    HMODULE hNtdll = myGetModuleHandleH(ntdll_dll);
    NtCreateMutant_t NtCreateMutant = (NtCreateMutant_t)myGetProcAddressH(hNtdll, ntcreatemutant);
    NtClose_t NtClose = (NtClose_t)myGetProcAddressH(hNtdll, ntclose);
    NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)myGetProcAddressH(hNtdll, ntqueryinformationprocess);

    PROCESS_SESSION_INFORMATION psi;
    NtQueryInformationProcess((HANDLE)-1, ProcessSessionInformation, &psi, sizeof(psi), NULL);

    int prefix_len = 0; while (prefix[prefix_len]) prefix_len++;
    int mutex_len = 0; while (mutex[mutex_len]) mutex_len++;

    int sid_len = 0;
    ULONG temp_v = psi.SessionId;
    if (temp_v == 0) sid_len = 1;
    else { while (temp_v > 0) { temp_v /= 10; sid_len++; } }

    wchar_t path[prefix_len + sid_len + mutex_len + 1];
    wchar_t *p = path;

    for (int i = 0; i < prefix_len; i++) *p++ = prefix[i];

    p += sid_len;
    wchar_t *digit_ptr = p;
    ULONG v = psi.SessionId;
    if (v == 0) *(--digit_ptr) = L'0';
    else { while (v > 0) { *(--digit_ptr) = L'0' + (v % 10); v /= 10; } }

    for (int i = 0; i < mutex_len; i++) *p++ = mutex[i];
    *p = L'\0';

    UNICODE_STRING name;
    name.Buffer = path;
    name.Length = (USHORT)((p - path) * sizeof(wchar_t));
    name.MaximumLength = sizeof(path);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hMutex;
    NTSTATUS status = NtCreateMutant(&hMutex, 0, &oa, FALSE);

    if (!NT_SUCCESS(status))
        myExitProcess(0);

    STRINGA(hello_str, "Hello from single instance!\n");
    STDOUT_WRITE(hello_str);
    mySleep(60000);

    NtClose(hMutex);
}
