#ifndef WINAPI_LOADER_H
#define WINAPI_LOADER_H

#include <windows.h>
#include <winternl.h>

// -------------------- String macros --------------------
#define STRINGA(name, value) __attribute__((section(".text"))) static char name[] = value;
#define STRINGW(name, value) __attribute__((section(".text"))) static wchar_t name[] = L##value;

// -------------------- XOR helpers (-DXOR) --------------------
#ifdef XOR

#define XOR_KEY(len) ( \
    ((len * 59) & 0xFF) ^ \
    (__DATE__[10] * 37 ^ __DATE__[9] * 31 ^ __DATE__[8] * 29) ^ \
    (__TIME__[3] * 7 ^ __TIME__[1] * 31 ^ __TIME__[0] * 17 ^ __TIME__[2] * 13) ^ \
    (__DATE__[7] * 23 ^ __DATE__[5] * 17 ^ __DATE__[6] * 19 ^ __DATE__[4] * 13) ^ \
    (__TIME__[6] * 29 ^ __TIME__[4] * 23 ^ __TIME__[5] * 19 ^ __TIME__[7] * 11) ^ \
    (__DATE__[3] * 11 ^ __DATE__[2] * 7 ^ __DATE__[1] * 5 ^ __DATE__[0] * 3) \
)

static void xor_decode(char* str) {
    size_t len = 0;
    while (str[len]) len++;
    unsigned char key = XOR_KEY(len);
    for (size_t i = 0; i < len; i++)
        str[i] ^= key;
}

#endif // XOR

// -------------------- PEB structs --------------------
typedef struct _LDR_MODULE {
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
  PVOID BaseAddress;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
  ULONG Flags;
  SHORT LoadCount;
  SHORT TlsIndex;
  LIST_ENTRY HashTableEntry;
  ULONG TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

// -------------------- Helpers --------------------
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

static void InitUnicodeString(UNICODE_STRING* ustr, const wchar_t* wstr) {
    size_t len = 0;
    while (wstr[len]) len++;

    ustr->Buffer        = (PWSTR)wstr;
    ustr->Length        = (USHORT)(len * sizeof(WCHAR));
    ustr->MaximumLength = (USHORT)((len + 1) * sizeof(WCHAR));
}

// -------------------- myGetModuleHandleA --------------------
static HMODULE myGetModuleHandleA(const char* name) {
    PEB* peb = (PEB*)__readgsqword(0x60);
    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;

    for (LIST_ENTRY* cur = head->Flink; cur != head; cur = cur->Flink) {
        PLDR_MODULE mod = (PLDR_MODULE)((BYTE*)cur - offsetof(LDR_MODULE, InMemoryOrderModuleList));
        SIZE_T len = mod->BaseDllName.Length / sizeof(WCHAR);
        SIZE_T i;
        for (i = 0; i < len && ((char)(mod->BaseDllName.Buffer[i]) | 0x20) == (name[i] | 0x20); ++i);
        if (i == len && name[i] == 0)
            return (HMODULE)mod->BaseAddress;
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
    char stackbuf[21];

    char* ntdll_dll = &stackbuf[0]; // 10 bytes
	char* ldrloaddll = &stackbuf[10]; // 11 bytes
#ifdef XOR
    ntdll_dll[0] = 'n'^XOR_KEY(9); ntdll_dll[1] = 't'^XOR_KEY(9);
    ntdll_dll[2] = 'd'^XOR_KEY(9); ntdll_dll[3] = 'l'^XOR_KEY(9);
    ntdll_dll[4] = 'l'^XOR_KEY(9); ntdll_dll[5] = '.'^XOR_KEY(9);
    ntdll_dll[6] = 'd'^XOR_KEY(9); ntdll_dll[7] = 'l'^XOR_KEY(9);
    ntdll_dll[8] = 'l'^XOR_KEY(9); ntdll_dll[9] = 0;
    xor_decode(ntdll_dll);
	
	ldrloaddll[0] = 'L'^XOR_KEY(10); ldrloaddll[1] = 'd'^XOR_KEY(10);
    ldrloaddll[2] = 'r'^XOR_KEY(10); ldrloaddll[3] = 'L'^XOR_KEY(10);
    ldrloaddll[4] = 'o'^XOR_KEY(10); ldrloaddll[5] = 'a'^XOR_KEY(10);
    ldrloaddll[6] = 'd'^XOR_KEY(10); ldrloaddll[7] = 'D'^XOR_KEY(10);
    ldrloaddll[8] = 'l'^XOR_KEY(10); ldrloaddll[9] = 'l'^XOR_KEY(10);
    ldrloaddll[10] = 0;
    xor_decode(ldrloaddll);
#else
    ntdll_dll[0] = 'n'; ntdll_dll[1] = 't'; ntdll_dll[2] = 'd';
    ntdll_dll[3] = 'l'; ntdll_dll[4] = 'l'; ntdll_dll[5] = '.';
    ntdll_dll[6] = 'd'; ntdll_dll[7] = 'l'; ntdll_dll[8] = 'l';
    ntdll_dll[9] = 0;
	
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
static HMODULE myLoadLibraryA(const char* dllNameA) {
    size_t len = 0;
    while (dllNameA[len]) len++;
    wchar_t buf[len + 1];

    UNICODE_STRING ustr;
    AsciiToWideChar(dllNameA, &ustr, buf, len + 1);
    return _myLdrLoadDll(&ustr);
}

// -------------------- myLoadLibraryW --------------------
static HMODULE myLoadLibraryW(const wchar_t* dllNameW) {
    UNICODE_STRING ustr;
    InitUnicodeString(&ustr, dllNameW);
    return _myLdrLoadDll(&ustr);
}

#endif // WINAPI_LOADER_H
