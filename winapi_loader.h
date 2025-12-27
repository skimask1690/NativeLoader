#ifndef WINAPI_LOADER_H
#define WINAPI_LOADER_H

#include <windows.h>

// -------------------- Optional string helpers --------------------
#define STRINGA(name, value) __attribute__((section(".text"))) static char name[] = value;
#define STRINGW(name, value) __attribute__((section(".text"))) static wchar_t name[] = L##value;

// -------------------- XOR helpers (-DXOR) --------------------
#ifdef XOR

#define MIX8(x) (x) ^ ((x) >> 4) ^ ((x) * 17)

#define XOR_KEY(len) \
    MIX8( \
        (__DATE__[2] * 131) ^ (__TIME__[5] * 193) ^ (__DATE__[7] * 197) ^ \
        (__TIME__[0] * 199) ^ (__DATE__[0] * 211) ^ (__TIME__[3] * 223) ^ \
        ((len) * 251) \
    )

#define NTDLL_NONCE 9
#define LDRLOADDLL_NONCE 10

static void xor_decode(char* str) {
    size_t len = 0;
    while (str[len]) len++;
    unsigned char key = XOR_KEY(len);
    for (size_t i = 0; i < len; i++)
        str[i] ^= key;
}

#endif // XOR

// -------------------- PEB structs --------------------
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    UCHAR Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PEB_LDR_DATA* Ldr;
} PEB;

// -------------------- myGetModuleHandleA --------------------
static HMODULE myGetModuleHandleA(const char* name) {
    PEB* peb = (PEB*)__readgsqword(0x60);
    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;

    for (LIST_ENTRY* cur = head->Flink; cur != head; cur = cur->Flink) {
        LDR_DATA_TABLE_ENTRY* ent = (LDR_DATA_TABLE_ENTRY*)((BYTE*)cur - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
        SIZE_T len = ent->BaseDllName.Length / sizeof(WCHAR);
        SIZE_T i;
        for (i = 0; i < len && ((char)ent->BaseDllName.Buffer[i] | 0x20) == (name[i] | 0x20); ++i);
        if (i == len && name[i] == 0)
            return (HMODULE)ent->DllBase;
    }

    return NULL;
}

// -------------------- myGetProcAddress --------------------
static FARPROC myGetProcAddress(HMODULE hMod, const char* fnName) {
    BYTE* base = (BYTE*)hMod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)
        (base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD* ords  = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* p1 = (const char*)(base + names[i]);
        const char* p2 = fnName;
        while (*p1 && (*p1) == (*p2)) { ++p1; ++p2; }
        if (*p2 == 0)
            return (FARPROC)(base + funcs[ords[i]]);
    }
    return NULL;
}

// -------------------- myLoadLibrary helper --------------------
typedef NTSTATUS(NTAPI* LdrLoadDll_t)(
    PWSTR PathToFile,
    ULONG Flags,
    UNICODE_STRING* ModuleFileName,
    PHANDLE ModuleHandle
);

static HMODULE _myLdrLoadDll(UNICODE_STRING* ustr) {
    unsigned char stackbuf[21];

    char* ntdll_dll = (char*)&stackbuf[0]; // 10 bytes
#ifdef XOR
    ntdll_dll[0] = 'n'^XOR_KEY(NTDLL_NONCE); ntdll_dll[1] = 't'^XOR_KEY(NTDLL_NONCE); ntdll_dll[2] = 'd'^XOR_KEY(NTDLL_NONCE);
    ntdll_dll[3] = 'l'^XOR_KEY(NTDLL_NONCE); ntdll_dll[4] = 'l'^XOR_KEY(NTDLL_NONCE); ntdll_dll[5] = '.'^XOR_KEY(NTDLL_NONCE);
    ntdll_dll[6] = 'd'^XOR_KEY(NTDLL_NONCE); ntdll_dll[7] = 'l'^XOR_KEY(NTDLL_NONCE); ntdll_dll[8] = 'l'^XOR_KEY(NTDLL_NONCE);
    ntdll_dll[9] = 0;
    xor_decode(ntdll_dll);
#else
    ntdll_dll[0] = 'n'; ntdll_dll[1] = 't'; ntdll_dll[2] = 'd';
    ntdll_dll[3] = 'l'; ntdll_dll[4] = 'l'; ntdll_dll[5] = '.';
    ntdll_dll[6] = 'd'; ntdll_dll[7] = 'l'; ntdll_dll[8] = 'l';
    ntdll_dll[9] = 0;
#endif

    char* ldrloaddll = (char*)&stackbuf[10]; // 11 bytes
#ifdef XOR
    ldrloaddll[0] = 'L'^XOR_KEY(LDRLOADDLL_NONCE); ldrloaddll[1] = 'd'^XOR_KEY(LDRLOADDLL_NONCE); ldrloaddll[2] = 'r'^XOR_KEY(LDRLOADDLL_NONCE);
    ldrloaddll[3] = 'L'^XOR_KEY(LDRLOADDLL_NONCE); ldrloaddll[4] = 'o'^XOR_KEY(LDRLOADDLL_NONCE); ldrloaddll[5] = 'a'^XOR_KEY(LDRLOADDLL_NONCE);
    ldrloaddll[6] = 'd'^XOR_KEY(LDRLOADDLL_NONCE); ldrloaddll[7] = 'D'^XOR_KEY(LDRLOADDLL_NONCE); ldrloaddll[8] = 'l'^XOR_KEY(LDRLOADDLL_NONCE);
    ldrloaddll[9] = 'l'^XOR_KEY(LDRLOADDLL_NONCE); ldrloaddll[10] = 0;
    xor_decode(ldrloaddll);
#else
    ldrloaddll[0] = 'L'; ldrloaddll[1] = 'd'; ldrloaddll[2] = 'r';
    ldrloaddll[3] = 'L'; ldrloaddll[4] = 'o'; ldrloaddll[5] = 'a';
    ldrloaddll[6] = 'd'; ldrloaddll[7] = 'D'; ldrloaddll[8] = 'l';
    ldrloaddll[9] = 'l'; ldrloaddll[10] = 0;
#endif

    HMODULE hNtdll = myGetModuleHandleA(ntdll_dll);
    LdrLoadDll_t pLdrLoadDll = (LdrLoadDll_t)myGetProcAddress(hNtdll, ldrloaddll);

    HMODULE hModule = NULL;
    pLdrLoadDll(NULL, 0, ustr, (PHANDLE)&hModule);

    return hModule;
}

// -------------------- myLoadLibraryA --------------------
static void AsciiToWideChar(const char* ascii, UNICODE_STRING* ustr, wchar_t* buf, SIZE_T bufCount) {
    SIZE_T i = 0;
    while (ascii[i] && i < bufCount - 1) {
        buf[i] = (wchar_t)ascii[i];
        i++;
    }
    buf[i] = 0;

    ustr->Length = (USHORT)(i * sizeof(wchar_t));
    ustr->MaximumLength = (USHORT)((i + 1) * sizeof(wchar_t));
    ustr->Buffer = buf;
}

static HMODULE myLoadLibraryA(const char* dllNameA) {
    size_t len = 0;
    while (dllNameA[len]) len++;
    wchar_t buf[len + 1];

    UNICODE_STRING ustr;
    AsciiToWideChar(dllNameA, &ustr, buf, len + 1);
    return _myLdrLoadDll(&ustr);
}

// -------------------- myLoadLibraryW --------------------
static void InitUnicodeString(UNICODE_STRING* ustr, const wchar_t* wstr) {
    size_t len = 0;
    while (wstr[len]) len++;

    ustr->Buffer        = (PWSTR)wstr;
    ustr->Length        = (USHORT)(len * sizeof(WCHAR));
    ustr->MaximumLength = (USHORT)((len + 1) * sizeof(WCHAR));
}

static HMODULE myLoadLibraryW(const wchar_t* dllNameW) {
    UNICODE_STRING ustr;
    InitUnicodeString(&ustr, dllNameW);
    return _myLdrLoadDll(&ustr);
}

#endif // WINAPI_LOADER_H
